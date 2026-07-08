package server

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/logger"
	"SmileVPN/internal/packets"
	"SmileVPN/server/users"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	addr                      string
	conn                      *net.TCPConn
	user                      *users.User //nolint:unuse
	countRecv                 atomic.Uint32
	countSent                 atomic.Uint32
	countRecvBytes            atomic.Uint32
	countSentBytes            atomic.Uint32
	sessionSentKey            *crypto.Key
	sessionRecvKey            *crypto.Key
	createdAt                 time.Time
	lastActive                time.Time
	lastRoundECDH             time.Time
	updateThroughSalt         bool
	roundECDHLock             chan struct{}
	ephemeralPrivateServerKey *ecdh.PrivateKey
	logger                    *logger.Logger
	localIP                   *net.IP
	mu                        sync.RWMutex
}

func (c *Client) computeNextSessionRecvKey(salt []byte) error {
	return c.sessionRecvKey.UpdateKey(salt)
}

func (c *Client) computeNextSessionSentKey(salt []byte) error {
	return c.sessionSentKey.UpdateKey(salt)
}

func (c *Client) write(data []byte) error {
	err := c.conn.SetWriteDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		return fmt.Errorf("failed to set write deadline: %v", err)
	}

	for {
		_, err = c.conn.Write(data)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				err = c.conn.SetWriteDeadline(time.Now().Add(time.Second * 1))
				if err != nil {
					return fmt.Errorf("failed to set write deadline: %v", err)
				}
				continue
			}
			return err
		}
		break
	}
	return nil
}

func (c *Client) handleTunnelPacket(rawPacket []byte) (error, bool) {
	if c.roundECDHLock != nil {
		c.logger.Trace("Waiting for ECDH lock for client %s", c.addr)
		<-c.roundECDHLock
		c.logger.Trace("ECDH lock acquired for client %s", c.addr)
	}

	salt := []byte{}
	if c.updateThroughSalt {
		salt, err := crypto.RandomBytes(8)
		if err != nil {
			c.logger.Error("Failed to generate salt for client %s: %v", c.addr, err)
			return err, false
		}
		c.logger.Trace("Salt generated for client %s: %x", c.addr, salt)

	}

	packet := packets.NewPlainPacket()
	packet.AddData(rawPacket)
	packet.AddParameter("salt", salt)

	needsECDH := c.countSent.Load() >= uint32(math.Pow(2, 16)) || time.Since(c.lastRoundECDH) >= 4*time.Minute
	c.logger.Trace("Client %s: countSent=%d, lastRoundECDH=%v, needsECDH=%v",
		c.addr, c.countSent.Load(), time.Since(c.lastRoundECDH), needsECDH)

	if needsECDH {
		c.logger.Debug("Initiating ECDH rekey for client %s (countSent=%d, lastRoundECDH=%v)",
			c.addr, c.countSent.Load(), time.Since(c.lastRoundECDH))

		curve := ecdh.X25519()
		privateKey, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			c.logger.Error("Failed to generate ephemeral key for client %s: %v", c.addr, err)
			return err, false
		}
		c.logger.Trace("Ephemeral key pair generated for client %s", c.addr)

		c.ephemeralPrivateServerKey = privateKey
		packet.AddParameter("publicKey", privateKey.PublicKey().Bytes())
		err = packet.PackageAssembly(c.sessionSentKey.GetBytes(), false, false)
		if err != nil {
			c.logger.Error("Failed to package packet with ECDH for client %s: %v", c.addr, err)
			return err, false
		}
		c.logger.Trace("Packet assembled with ECDH flag for client %s", c.addr)
	} else {
		err := packet.PackageAssembly(c.sessionSentKey.GetBytes(), false, false)
		if err != nil {
			c.logger.Error("Failed to package packet for client %s: %v", c.addr, err)
			return err, false
		}
		c.logger.Trace("Packet assembled without ECDH flag for client %s", c.addr)
	}

	err := c.write(packet.GetRawData())
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.logger.Info("Client %s connection closed, releasing IP %s", c.addr, c.localIP.String())
			return err, true
		}
		c.logger.Error("Failed to write packet to client %s: %v", c.addr, err)
		return err, false
	}
	c.logger.Trace("Packet written to client %s, size=%d bytes", c.addr, len(packet.GetRawData()))

	if packet.GetEcdhFlag() {
		c.logger.Debug("ECDH flag set for client %s, creating lock", c.addr)
		c.roundECDHLock = make(chan struct{}, 1)
	}

	if c.updateThroughSalt {
		err = c.computeNextSessionSentKey(salt)
		if err != nil {
			c.logger.Error("Failed to compute next session sent key for client %s: %v", c.addr, err)
			return err, false
		}
	}
	c.countSent.Add(1)
	c.logger.Trace("Client %s: session sent key updated, countSent=%d", c.addr, c.countSent.Load())
	return nil, false
}

func (c *Client) handlePacket() ([]byte, error, bool) {
	packet, err := c.readPacket()
	if err != nil {
		if errors.Is(err, net.ErrClosed) {
			c.logger.Info("Client %s connection closed (net.ErrClosed), releasing IP %s", c.addr, c.localIP.String())
			return nil, err, true
		}

		if errors.Is(err, io.EOF) {
			c.logger.Info("Client %s disconnected (EOF), releasing IP %s", c.addr, c.localIP.String())
			return nil, err, true
		}
		c.logger.Error("Failed to read packet from client %s: %v", c.addr, err)
		return nil, err, false
	}
	c.logger.Trace("Packet received from client %s, size=%d bytes", c.addr, len(packet.GetRawData()))

	err = packet.DecodeAndDecrypt(c.sessionRecvKey.GetBytes())
	if err != nil {
		c.logger.Error("Failed to decrypt packet from client %s: %v", c.addr, err)
		return nil, err, false
	}
	c.logger.Trace("Packet decrypted successfully for client %s", c.addr)
	if packet.GetDisconnectFlag() {
		c.logger.Info("Client %s disconnected, releasing IP %s", c.addr, c.localIP.String())
		return nil, err, true
	}

	c.countRecv.Add(1)
	salt := packet.GetSalt()
	if len(salt) != 0 {
		err = c.computeNextSessionRecvKey(salt)
		if err != nil {
			c.logger.Error("Failed to compute next session recv key for client %s: %v", c.addr, err)
			return nil, err, true
		}
		c.logger.Trace("Client %s: countRecv=%d, session recv key updated", c.addr, c.countRecv.Load())
	}

	if packet.GetEcdhFlag() && c.ephemeralPrivateServerKey != nil {
		c.logger.Debug("Processing ECDH rekey from client %s", c.addr)

		curve := ecdh.X25519()
		clientPublicKey, err := curve.NewPublicKey(packet.GetPublicKey())
		if err != nil {
			c.logger.Error("Failed to parse client public key for %s: %v", c.addr, err)
			return nil, err, true
		}
		c.logger.Trace("Client public key parsed for %s", c.addr)

		secret, err := c.ephemeralPrivateServerKey.ECDH(clientPublicKey)
		if err != nil {
			c.logger.Error("Failed to compute shared secret for client %s: %v", c.addr, err)
			return nil, err, true
		}
		c.logger.Trace("Shared secret computed for client %s", c.addr)

		c.ephemeralPrivateServerKey = nil
		c.lastRoundECDH = time.Now()

		c.countRecv.Store(0)
		c.countSent.Store(0)
		c.logger.Trace("Client %s: counters reset (recv=0, sent=0), lastRoundECDH updated", c.addr)

		err = c.computeNextSessionSentKey(secret)
		if err != nil {
			c.logger.Error("Failed to compute next session sent key for %s: %v", c.addr, err)
			return nil, err, true
		}
		err = c.computeNextSessionRecvKey(secret)
		if err != nil {
			c.logger.Error("Failed to compute next session recv key for %s: %v", c.addr, err)
			return nil, err, true
		}
		c.CloseECDHLock()

		c.logger.Info("ECDH rekey completed for client %s", c.addr)
	}

	c.mu.Lock()
	c.lastActive = time.Now()

	countRecv := len(packet.GetRawData())
	if countRecv < 0 {
		countRecv = 0
	}

	c.countRecvBytes.Add(uint32(countRecv))
	c.mu.Unlock()
	c.logger.Trace("Client %s: lastActive updated, countRecvBytes=%d", c.addr, c.countRecvBytes.Load())

	ipSrc, err := packet.GetSlicePlainData(12, 16)
	if err != nil {
		c.logger.Error("Failed to get source IP from packet for client %s: %v", c.addr, err)
		return nil, err, false
	}

	srcIP := fmt.Sprintf("%d.%d.%d.%d", ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3])
	if srcIP != c.localIP.String() {
		c.logger.Error("Source IP mismatch for client %s: expected %s, got %s", c.addr, c.localIP.String(), srcIP)
		return nil, err, false
	}
	c.logger.Trace("Source IP validated for client %s: %s", c.addr, srcIP)

	return packet.GetPlainData(), nil, false
}

func (c *Client) readPacket() (packet *packets.StreamingPacket, err error) {
	lenPacketBytes, err := c.read(5)
	if err != nil {
		return nil, err
	}

	packet = packets.NewRawPacket()
	packet.AddData(lenPacketBytes)

	lenPacket := binary.BigEndian.Uint16(lenPacketBytes[3:5])

	rawPacket, err := c.read(lenPacket)
	if err != nil {
		return nil, err
	}
	packet.AddData(rawPacket)

	return packet, nil
}

func (c *Client) read(length uint16) (data []byte, err error) {
	if length == 0 {
		return []byte{}, nil
	}

	data = make([]byte, length)
	remaining := length
	offset := 0

	err = c.conn.SetReadDeadline(time.Now().Add(time.Second * 1))
	if err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %v", err)
	}
	for remaining > 0 {
		n, err := c.conn.Read(data[offset:])
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				err = c.conn.SetReadDeadline(time.Now().Add(time.Second * 1))
				if err != nil {
					return nil, fmt.Errorf("failed to set read deadline: %v", err)
				}
				continue
			}
			return nil, err
		}
		if n < 0 {
			n = 0
		}

		remaining -= uint16(n)
		offset += n
	}

	return data, nil
}

func (c *Client) CloseECDHLock() {
	select {
	case _, ok := <-c.roundECDHLock:
		if ok {
			close(c.roundECDHLock)
		}
	default:
		if c.roundECDHLock != nil {
			close(c.roundECDHLock)
		}
	}
}

func (c *Client) Close() error {
	c.CloseECDHLock()
	return c.conn.Close()
}
