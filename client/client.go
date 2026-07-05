package client

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/logger"
	"SmileVPN/internal/packets"
	"SmileVPN/internal/tunnel"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"reflect"
	"sync"
	"time"
	"unsafe"

	tls "github.com/refraction-networking/utls"
)

type Client struct {
	host                     string
	hostName                 string
	port                     int
	initPassword             [32]byte
	username                 [16]byte
	password                 [16]byte
	conn                     *net.TCPConn
	sessionSentKey           *crypto.Key
	sessionRecvKey           *crypto.Key
	secretECDH               []byte
	packetBuffer             []*packets.StreamingPacket
	sizeBatch                int
	tunnel                   *tunnel.Tunnel
	logger                   *logger.Logger
	countRecv                uint32
	countSent                uint32
	updateThroughSalt        bool
	batching                 bool
	ephemeralPublicClientKey *ecdh.PublicKey
	bufferLock               sync.Mutex

	wg     sync.WaitGroup
	stopCh chan struct{}
}

func NewClient(host, hostName string, port int, initPassword [32]byte, username, password [16]byte, updateThroughSalt, batching bool, logger *logger.Logger) (client *Client, err error) {
	logger.Trace("Creating new client instance for %s:%d", host, port)
	return &Client{
		host:              host,
		hostName:          hostName,
		port:              port,
		initPassword:      initPassword,
		username:          username,
		password:          password,
		logger:            logger,
		packetBuffer:      []*packets.StreamingPacket{},
		updateThroughSalt: updateThroughSalt,
		batching:          batching,
		sessionSentKey:    crypto.NewKey(sha256.New()),
		sessionRecvKey:    crypto.NewKey(sha256.New()),
		sizeBatch:         1,
		stopCh:            make(chan struct{}),
	}, nil
}

func (c *Client) Run() (err error) {
	addr := net.JoinHostPort(c.host, fmt.Sprintf("%d", c.port))
	c.logger.Info("Connected to the server at %s", addr)
	c.logger.Debug("Attempting TCP connection to %s with timeout 10s", addr)

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.logger.Error("Server connection error: %v", err)
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.logger.Info("Connection established")

	tlsConfig := &tls.Config{
		ServerName: c.hostName,
	}

	tlsConn := tls.UClient(conn, tlsConfig, tls.HelloFirefox_120)

	err = tlsConn.Handshake()
	if err != nil {
		c.logger.Error("error handshake: %v", err)
		return err
	}

	c.conn = GetRawConn(tlsConn).(*net.TCPConn)
	time.Sleep(time.Millisecond * 100)

	c.logger.Debug("Local address: %s, Remote address: %s", c.conn.LocalAddr(), c.conn.RemoteAddr())

	c.logger.Info("A handshake with the server has begun")
	c.sessionRecvKey.SetKey(c.initPassword[:])
	c.sessionSentKey.SetKey(c.initPassword[:])
	c.logger.Trace("Initial session keys set (both recv and sent)")

	packet := packets.NewPlainPacket()

	timestampBytes := make([]byte, 8)
	now := time.Now().Unix()
	if now < 0 {
		now = 0
	}

	binary.BigEndian.PutUint64(timestampBytes, uint64(now))
	c.logger.Trace("Timestamp created: %d (unix)", now)

	packet.AddData(c.username[:])
	packet.AddData(timestampBytes)
	c.logger.Debug("Username packet prepared with timestamp")

	err = packet.PackageAssembly(c.initPassword[:], false, false, false)
	if err != nil {
		c.logger.Error("Assembly error in the username packet: %v", err)
		return err
	}
	c.logger.Trace("Username packet assembled successfully, size: %d bytes", len(packet.GetRawData()))

	if _, err = c.conn.Write(packet.GetRawData()); err != nil {
		c.logger.Error("Error sending a packet with the username: %v", err)
		return err
	}
	c.logger.Debug("Username packet sent to server")

	saltPacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the salt packet: %v", err)
		return err
	}
	c.logger.Trace("Salt packet received")

	err = saltPacket.DecodeAndDecrypt(c.initPassword[:])
	if err != nil {
		c.logger.Error("Error decoding or decrypting the salt packet: %v", err)
		return err
	}
	c.logger.Debug("Salt packet decrypted successfully")

	firstSalt, err := saltPacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Error retrieving the first 16 bytes from the salt packet (first salt): %v", err)
		return fmt.Errorf("error when attempting to retrieve the first salt: %v", err)
	}

	secondSalt, err := saltPacket.GetSlicePlainData(16, 32)
	if err != nil {
		c.logger.Error("Error retrieving the second 16 bytes from the salt packet (second salt): %v", err)
		return fmt.Errorf("error when attempting to retrieve the second salt: %v", err)
	}
	c.logger.Trace("First and second salt extracted")

	c.sessionSentKey.SetKey(c.password[:])
	c.sessionSentKey.UpdateKey(firstSalt)
	c.logger.Trace("Session sent key derived from first salt")

	c.sessionRecvKey.SetKey(c.password[:])
	c.sessionRecvKey.UpdateKey(secondSalt)
	c.logger.Trace("Session recv key derived from second salt")

	okPacket := packets.NewPlainPacket()
	okPacket.AddData([]byte{0xFF})
	c.logger.Debug("Confirmation packet created (0xFF)")

	curve := ecdh.X25519()
	privateClientKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		c.logger.Error("Error generating a key pair for ECDH: %v", err)
		return err
	}
	publicClientKey := privateClientKey.PublicKey()
	c.logger.Debug("ECDH key pair generated")

	okPacket.AddParameter("publicKey", publicClientKey.Bytes())
	err = okPacket.PackageAssembly(c.sessionSentKey.GetBytes(), false, true, false)
	if err != nil {
		c.logger.Error("Assembly error in the packet with connection verification and public key for ECDH: %v", err)
		return err
	}
	c.logger.Trace("Confirmation packet assembled with ECDH flag")

	if _, err = c.conn.Write(okPacket.GetRawData()); err != nil {
		c.logger.Error("Error sending a packet containing the connection confirmation and public key for ECDH: %v", err)
		return err
	}
	c.logger.Debug("Confirmation packet sent to server")

	ipPacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the ip packet: %v", err)
		return err
	}
	c.logger.Trace("IP packet received")

	err = ipPacket.DecodeAndDecrypt(c.sessionRecvKey.GetBytes())
	if err != nil {
		c.logger.Error("Error decoding or decrypting the ip packet: %v", err)
		return err
	}
	c.logger.Debug("IP packet decrypted")

	ipBytes, err := ipPacket.GetSlicePlainData(0, 4)
	if err != nil {
		c.logger.Error("Error retrieving the first 4 bytes (IP address) from the packet with IP: %v", err)
		return fmt.Errorf("error when attempting to retrieve the IP address: %v", err)
	}
	c.logger.Debug("Assigned IP from server: %d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])

	publicServerKey, err := curve.NewPublicKey(ipPacket.GetPublicKey())
	if err != nil {
		c.logger.Error("Error parsing the server's public key for ECDH: %v", err)
		return err
	}
	c.logger.Trace("Server public key parsed")

	secret, err := privateClientKey.ECDH(publicServerKey)
	if err != nil {
		c.logger.Error("ECDH execution error: %v", err)
		return err
	}
	c.logger.Debug("ECDH shared secret computed")

	c.computeNextSessionRecvKey(secret)
	c.computeNextSessionSentKey(secret)
	c.logger.Trace("Session keys updated with ECDH secret")

	tun, err := tunnel.NewTunnel(
		"smile-tun0",
		1500,
		net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])),
		net.IPv4Mask(255, 255, 255, 0),
	)

	if err != nil {
		c.logger.Error("Error create tunnel: %v", err)
		return fmt.Errorf("error create tunnel: %v", err)
	}

	c.tunnel = &tun
	c.logger.Debug("Tunnel interface created: smile-tun0, MTU: 1500")

	c.logger.Info("The handshake with the server was successful")

	c.logger.Info("Starting the main VPN operation cycle")
	c.wg.Add(2)
	go c.readerTunnel()
	c.logger.Trace("Tunnel reader goroutine started")

	go c.writerTunnel()
	c.logger.Trace("Tunnel writer goroutine started")

	return nil
}

func (c *Client) Stop() error {
	c.logger.Info("Stopping client")
	c.logger.Debug("Closing stop channel")
	close(c.stopCh)
	c.logger.Trace("Waiting for goroutines to finish")
	err := (*c.tunnel).Close(false, true)
	if err != nil {
		c.logger.Error("Tunnel close error: %v", err)
		return err
	}

	c.wg.Wait()
	packet := packets.NewPlainPacket()
	err = packet.PackageAssembly(c.sessionSentKey.GetBytes(), false, false, true)
	if err != nil {
		c.logger.Error("Assembly error in the packet: %v", err)
		return nil
	}
	c.packetBuffer = []*packets.StreamingPacket{packet}
	c.sendBuffer()
	c.conn.Close()
	c.logger.Debug("Closing tunnel interface")
	c.logger.Info("The client has been stopped")

	return nil
}

func (c *Client) writerTunnel() {
	c.logger.Debug("Writer tunnel goroutine started")
	defer func() {
		c.logger.Trace("Writer tunnel goroutine finishing")
		c.wg.Done()
	}()

	var secret []byte
	for {
		select {
		case <-c.stopCh:
			c.logger.Debug("Writer tunnel received stop signal")
			return
		default:
			packet, err := c.readPacket()
			if err != nil {
				if err.Error() == "EOF" {
					c.logger.Debug("Writer tunnel: EOF received, stopping client")
					return
				}
				c.logger.Error("Writer tunnel: error reading packet: %v", err)
				continue
			}
			c.countRecv++
			c.logger.Trace("Writer tunnel: packet received, countRecv=%d", c.countRecv)

			err = packet.DecodeAndDecrypt(c.sessionRecvKey.GetBytes())
			if err != nil {
				c.logger.Error("Error decoding or decrypting the packet: %v", err)
				continue
			}
			c.logger.Trace("Writer tunnel: packet decrypted successfully")

			_, err = (*c.tunnel).Write(packet.GetPlainData())
			if err != nil {
				c.logger.Error("Error writing a packet to the tunnel: %v", err)
				continue
			}
			c.logger.Trace("Writer tunnel: packet written to tunnel")

			salt := packet.GetSalt()
			if len(salt) != 0 {
				c.computeNextSessionRecvKey(salt)
			}
			c.logger.Trace("Writer tunnel: session recv key updated with salt")

			if packet.GetEcdhFlag() {
				c.logger.Debug("Writer tunnel: ECDH flag detected, initiating rekey")

				var publicServerKey *ecdh.PublicKey
				curve := ecdh.X25519()
				publicServerKey, err = curve.NewPublicKey(packet.GetPublicKey())
				if err != nil {
					c.logger.Error("Error parsing the server's public key for ECDH: %v", err)
					continue
				}
				c.logger.Trace("Writer tunnel: server public key parsed")

				privateKey, err := curve.GenerateKey(rand.Reader)
				if err != nil {
					c.logger.Error("Error generating a key pair for ECDH: %v", err)
					continue
				}
				c.logger.Trace("Writer tunnel: new key pair generated")

				secret, err = privateKey.ECDH(publicServerKey)
				if err != nil {
					c.logger.Error("ECDH execution error: %v", err)
					return
				}
				c.ephemeralPublicClientKey = privateKey.PublicKey()
				c.secretECDH = secret
				c.countRecv = 0
				c.computeNextSessionRecvKey(c.secretECDH)
				c.logger.Debug("Writer tunnel: ECDH rekey completed, countRecv reset to 0")
			}
		}
	}
}

func (c *Client) readerTunnel() {
	c.logger.Debug("Reader tunnel goroutine started")
	defer func() {
		c.logger.Trace("Reader tunnel goroutine finishing")
		c.wg.Done()
	}()

	c.logger.Debug("Bringing tunnel up")
	if err := (*c.tunnel).Up([]string{c.host}, true, false); err != nil {
		c.logger.Error("Tunnel upping error: %v", err)
		return
	}
	c.logger.Info("Tunnel is up and running")

	defer func() {
		c.logger.Debug("Bringing tunnel down")
		err := (*c.tunnel).Close(false, true)
		if err != nil {
			c.logger.Error("Tunnel down failed: %v", err)
		}
		c.logger.Info("Tunnel is down")
	}()

	rawPacket := make([]byte, (*c.tunnel).MTU())
	c.logger.Trace("Raw packet buffer created with MTU size: %d", (*c.tunnel).MTU())

	for {
		select {
		case <-c.stopCh:
			c.logger.Debug("Reader tunnel received stop signal")
			return
		default:
			n, err := (*c.tunnel).Read(rawPacket)
			if err != nil {
				if err == context.DeadlineExceeded {
					continue
				}
				c.logger.Error("Error reading a packet from the tunnel: %v", err)
				return
			}
			c.countSent++
			c.logger.Trace("Reader tunnel: packet read from tunnel, size=%d bytes, countSent=%d", n, c.countSent)

			packet := packets.NewPlainPacket()

			var salt []byte
			if c.updateThroughSalt {
				salt, err = crypto.RandomBytes(8)
				if err != nil {
					c.logger.Error("Salt generation error: %v", err)
					continue
				}

			}
			c.logger.Trace("Reader tunnel: salt generated (8 bytes)")

			packet.AddData(rawPacket[:n])
			packet.AddParameter("salt", salt)

			if c.ephemeralPublicClientKey != nil {
				c.logger.Debug("Reader tunnel: using ephemeral public key for ECDH")
				packet.AddParameter("publicKey", c.ephemeralPublicClientKey.Bytes())
				err = packet.PackageAssembly(c.sessionSentKey.GetBytes(), false, true, false)
				c.ephemeralPublicClientKey = nil
				c.logger.Trace("Reader tunnel: packet assembled with ECDH flag")
			} else {
				c.logger.Trace("Reader tunnel: no ephemeral key, assembling without ECDH")
				err = packet.PackageAssembly(c.sessionSentKey.GetBytes(), false, false, false)
			}

			if err != nil {
				c.logger.Error("Assembly error in the packet: %v", err)
				continue
			}

			c.write(packet)
			c.logger.Trace("Reader tunnel: packet queued for sending")

			if c.updateThroughSalt {
				c.computeNextSessionSentKey(salt)
			}
			c.logger.Trace("Reader tunnel: session sent key updated with salt")

			if packet.GetEcdhFlag() {
				c.logger.Debug("Reader tunnel: ECDH flag set, resetting countSent and updating keys with secret")
				c.countSent = 0
				c.computeNextSessionSentKey(c.secretECDH)
				c.logger.Trace("Reader tunnel: countSent reset to 0, session sent key updated with ECDH secret")
			}
		}
	}
}
func (c *Client) sendBuffer() {
	c.bufferLock.Lock()
	defer c.bufferLock.Unlock()

	for i, packet := range c.packetBuffer {
		rawData := packet.GetRawData()
		writeTimeout := 5 * time.Second

		for {
			select {
			case <-c.stopCh:
				c.logger.Info("Sender stopped, cancelling packet %d transmission", i)
				return
			default:
			}

			if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
				c.logger.Error("Failed to set write deadline: %v", err)
				return
			}

			_, err := c.conn.Write(rawData)

			if err == nil {
				c.logger.Trace("Sender: packet %d sent, size=%d bytes", i, len(rawData))
				break
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				c.logger.Error("Write timeout, retrying... (stop signal check in next iteration)")
				continue
			}

			c.logger.Error("Packet transmission unrecoverable error: %v", err)
			break
		}
	}

	n, err := rand.Int(rand.Reader, big.NewInt(4))
	if err != nil {
		c.logger.Error("Error generating batch size: %v", err)
	}

	c.sizeBatch = int(n.Int64()) + 1
	c.logger.Debug("Sender: batch size updated to %d", c.sizeBatch)

	c.packetBuffer = []*packets.StreamingPacket{}
}

func (c *Client) write(packet *packets.StreamingPacket) {
	if !c.batching {
		go func() {
			writeTimeout := 5 * time.Second
			rawData := packet.GetRawData()
			for {
				select {
				case <-c.stopCh:
					return
				default:
				}

				if err := c.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
					c.logger.Error("Failed to set write deadline: %v", err)
					return
				}

				_, err := c.conn.Write(rawData)
				if err == nil {
					c.logger.Trace("Sender: packet sent, size=%d bytes", len(rawData))
					break
				}

				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.logger.Error("Write timeout, retrying... (stop signal check in next iteration)")
					continue
				}

				c.logger.Error("Packet transmission unrecoverable error: %v", err)
				break
			}

			c.logger.Trace("Send packet, size=%d bytes", len(rawData))
		}()
		return
	}

	c.bufferLock.Lock()
	defer c.bufferLock.Unlock()

	c.packetBuffer = append(c.packetBuffer, packet)
	if len(c.packetBuffer) >= c.sizeBatch {
		go c.sendBuffer()
	}

	c.logger.Trace("Packet added to buffer, current buffer size: %d", len(c.packetBuffer))
}

func (c *Client) computeNextSessionSentKey(salt []byte) {
	c.sessionSentKey.UpdateKey(salt)
	c.logger.Trace("Session sent key updated (new hash computed)")
}

func (c *Client) computeNextSessionRecvKey(salt []byte) {
	c.sessionRecvKey.UpdateKey(salt)
	c.logger.Trace("Session recv key updated (new hash computed)")
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

	c.conn.SetReadDeadline(time.Now().Add(time.Second * 1))
	for remaining > 0 {
		select {
		case <-c.stopCh:
			return nil, errors.New("stoppig")
		default:
			n, err := c.conn.Read(data[offset:])
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					c.conn.SetReadDeadline(time.Now().Add(time.Second * 1))
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
	}

	return data, nil
}

func GetRawConn(tlsConn net.Conn) net.Conn {
	v := reflect.ValueOf(tlsConn).Elem()

	connField := v.FieldByName("conn")
	if !connField.IsValid() {
		panic("поле conn не найдено")
	}

	fieldPtr := unsafe.Pointer(connField.UnsafeAddr())

	connPtr := (*net.Conn)(fieldPtr)

	return *connPtr
}
