package client

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/logger"
	"SmileVPN/internal/packets"
	"SmileVPN/internal/tunnel"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"net"
	"sync"
	"time"
)

type Client struct {
	host                     string
	port                     int
	initPassword             [32]byte
	username                 [16]byte
	password                 [16]byte
	conn                     *net.TCPConn
	sessionSentKey           []byte
	sessionRecvKey           []byte
	secretECDH               []byte
	packetBuffer             []*packets.StreamingPacket
	sizeBatch                int
	tunnel                   *tunnel.Tunnel
	logger                   *logger.Logger
	countRecv                uint32
	countSent                uint32
	ephemeralPublicClientKey *ecdh.PublicKey
	hasher                   hash.Hash
	hasherLock               sync.Mutex
	bufferLock               sync.Mutex

	wg     sync.WaitGroup
	stopCh chan struct{}
}

func NewClient(host string, port int, initPassword [32]byte, username, password [16]byte, logger *logger.Logger) (client *Client, err error) {
	return &Client{
		host:         host,
		port:         port,
		initPassword: initPassword,
		username:     username,
		password:     password,
		logger:       logger,
		packetBuffer: []*packets.StreamingPacket{},
		sizeBatch:    1,
		hasher:       sha256.New(),
		stopCh:       make(chan struct{}),
	}, nil
}

func (c *Client) Run() (err error) {
	addr := net.JoinHostPort(c.host, fmt.Sprintf("%d", c.port))

	c.logger.Info("Connected to the server at %s", addr)
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.logger.Error("Server connection error: %v", err)
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.conn = conn.(*net.TCPConn)
	c.logger.Info("Connection established")

	c.logger.Info("A handshake with the server has begun")
	c.sessionRecvKey = c.initPassword[:]
	c.sessionSentKey = c.initPassword[:]

	packet := packets.NewPlainPacket()

	timestampBytes := make([]byte, 8)
	now := time.Now().Unix()
	if now < 0 {
		now = 0
	}

	binary.BigEndian.PutUint64(timestampBytes, uint64(now))

	packet.AddData(c.username[:])
	packet.AddData(timestampBytes)

	err = packet.PackageAssembly(c.initPassword[:], []byte{}, []byte{}, false, false)
	if err != nil {
		c.logger.Error("Assembly error in the username packet: %v", err)
		return err
	}

	if _, err = c.conn.Write(packet.GetRawData()); err != nil {
		c.logger.Error("Error sending a packet with the username: %v", err)
		return err
	}

	saltPacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the salt packet: %v", err)
		return err
	}

	err = saltPacket.DecodeAndDecrypt(c.initPassword[:], false)
	if err != nil {
		c.logger.Error("Error decoding or decrypting the salt packet: %v", err)
		return err
	}

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

	c.hasher.Reset()
	c.hasher.Write(c.password[:])
	c.hasher.Write([]byte(":"))
	c.hasher.Write(firstSalt)
	c.sessionSentKey = c.hasher.Sum(nil)

	c.hasher.Reset()
	c.hasher.Write(c.password[:])
	c.hasher.Write([]byte(":"))
	c.hasher.Write(secondSalt)
	c.sessionRecvKey = c.hasher.Sum(nil)

	okPacket := packets.NewPlainPacket()
	okPacket.AddData([]byte{0xFF})

	curve := ecdh.X25519()
	privateClientKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		c.logger.Error("Error generating a key pair for ECDH: %v", err)
		return err
	}
	publicClientKey := privateClientKey.PublicKey()

	err = okPacket.PackageAssembly(c.sessionSentKey, []byte{}, publicClientKey.Bytes(), false, true)
	if err != nil {
		c.logger.Error("Assembly error in the packet with connection verification and public key for ECDH: %v", err)
		return err
	}

	if _, err = c.conn.Write(okPacket.GetRawData()); err != nil {
		c.logger.Error("Error sending a packet containing the connection confirmation and public key for ECDH: %v", err)
		return err
	}

	ipPacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the ip packet: %v", err)
		return err
	}

	err = ipPacket.DecodeAndDecrypt(c.sessionRecvKey, false)
	if err != nil {
		c.logger.Error("Error decoding or decrypting the ip packet: %v", err)
		return err
	}

	ipBytes, err := ipPacket.GetSlicePlainData(0, 4)
	if err != nil {
		c.logger.Error("Error retrieving the first 4 bytes (IP address) from the packet with IP: %v", err)
		return fmt.Errorf("error when attempting to retrieve the IP address: %v", err)
	}

	publicServerKey, err := curve.NewPublicKey(ipPacket.GetPublicKey())
	if err != nil {
		c.logger.Error("Error parsing the server's public key for ECDH: %v", err)
		return err
	}

	secret, err := privateClientKey.ECDH(publicServerKey)
	if err != nil {
		c.logger.Error("ECDH execution error: %v", err)
		return err
	}
	c.computeNextSessionRecvKey(secret)
	c.computeNextSessionSentKey(secret)

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

	c.logger.Info("The handshake with the server was successful")

	c.logger.Info("Starting the main VPN operation cycle")
	c.wg.Add(3)
	go c.readerTunnel()

	go c.writerTunnel()

	go c.sender()

	return nil
}

func (c *Client) Stop() error {
	close(c.stopCh)
	c.wg.Wait()
	err := (*c.tunnel).Close()
	if err != nil {
		return err
	}
	c.logger.Info("The client has been updated")

	return nil
}

func (c *Client) writerTunnel() {
	defer c.wg.Done()
	var secret []byte
	for {
		select {
		case <-c.stopCh:
			return
		default:
			packet, err := c.readPacket()
			if err != nil {
				if err.Error() == "EOF" {
					c.wg.Done()
					c.Stop()
					return
				}
				continue
			}
			c.countRecv++

			err = packet.DecodeAndDecrypt(c.sessionRecvKey, true)
			if err != nil {
				c.logger.Error("Error decoding or decrypting the packet: %v", err)
				continue
			}

			_, err = (*c.tunnel).Write(packet.GetPlainData())
			if err != nil {
				c.logger.Error("Error writing a packet to the tunnel: %v", err)
				continue
			}

			c.computeNextSessionRecvKey(packet.GetSalt())

			if packet.GetEcdhFlag() {

				var publicServerKey *ecdh.PublicKey
				curve := ecdh.X25519()
				publicServerKey, err = curve.NewPublicKey(packet.GetPublicKey())
				if err != nil {
					c.logger.Error("Error parsing the server's public key for ECDH: %v", err)
					continue
				}

				privateKey, err := curve.GenerateKey(rand.Reader)
				if err != nil {
					c.logger.Error("Error generating a key pair for ECDH: %v", err)
					continue
				}

				secret, err = privateKey.ECDH(publicServerKey)
				if err != nil {
					c.logger.Error("ECDH execution error: %v", err)
					return
				}
				c.ephemeralPublicClientKey = privateKey.PublicKey()
				c.secretECDH = secret
				c.countRecv = 0
				c.computeNextSessionRecvKey(c.secretECDH)
			}
		}
	}
}

func (c *Client) readerTunnel() {
	defer c.wg.Done()

	if err := (*c.tunnel).Up([]string{c.host}); err != nil {
		c.logger.Error("Tunnel upping error: %v", err)
		return
	}
	defer func() {
		err := (*c.tunnel).Down()
		if err != nil {
			c.logger.Error("Tunnel down failed: %v", err)
		}
	}()

	rawPacket := make([]byte, (*c.tunnel).MTU())

	for {
		select {
		case <-c.stopCh:
			return
		default:
			n, err := (*c.tunnel).Read(rawPacket)
			if err != nil {
				c.logger.Error("Error reading a packet from the tunnel: %v", err)
				return
			}
			c.countSent++

			packet := packets.NewPlainPacket()

			salt, err := crypto.RandomBytes(8)
			if err != nil {
				c.logger.Error("Salt generation error: %v", err)
				continue
			}

			packet.AddData(rawPacket[:n])
			if c.ephemeralPublicClientKey != nil {
				err = packet.PackageAssembly(c.sessionSentKey, salt, c.ephemeralPublicClientKey.Bytes(), false, true)
				c.ephemeralPublicClientKey = nil
			} else {
				err = packet.PackageAssembly(c.sessionSentKey, salt, []byte{}, false, false)
			}
			if err != nil {
				c.logger.Error("Assembly error in the packet: %v", err)
				continue
			}

			c.write(packet)

			c.computeNextSessionSentKey(salt)
			if packet.GetEcdhFlag() {
				c.countSent = 0
				c.computeNextSessionSentKey(c.secretECDH)
			}
		}
	}
}

func (c *Client) sender() {
	defer c.wg.Done()
	for {
		select {
		case <-c.stopCh:
			return
		default:
			c.bufferLock.Lock()

			if len(c.packetBuffer) < c.sizeBatch {
				c.bufferLock.Unlock()
				continue
			}

			for _, packet := range c.packetBuffer {
				_, err := c.conn.Write(packet.GetRawData())
				if err != nil {
					c.logger.Error("Packet transmission error: %v", err)
				}
			}
			c.packetBuffer = []*packets.StreamingPacket{}
			n, err := rand.Int(rand.Reader, big.NewInt(4))
			if err != nil {
				c.logger.Error("Error generating batch size: %v", err)
			}

			c.sizeBatch = int(n.Int64()) + 1
			c.bufferLock.Unlock()
		}
	}
}

func (c *Client) write(packet *packets.StreamingPacket) {
	c.bufferLock.Lock()
	defer c.bufferLock.Unlock()

	c.packetBuffer = append(c.packetBuffer, packet)
}

func (c *Client) computeNextSessionSentKey(salt []byte) {
	c.hasherLock.Lock()
	defer c.hasherLock.Unlock()
	c.hasher.Reset()
	c.hasher.Write(c.sessionSentKey)
	c.hasher.Write([]byte(":"))
	c.hasher.Write(salt)
	c.sessionSentKey = c.hasher.Sum(nil)
}

func (c *Client) computeNextSessionRecvKey(salt []byte) {
	c.hasherLock.Lock()
	defer c.hasherLock.Unlock()
	c.hasher.Reset()
	c.hasher.Write(c.sessionRecvKey)
	c.hasher.Write([]byte(":"))
	c.hasher.Write(salt)
	c.sessionRecvKey = c.hasher.Sum(nil)
}

func (c *Client) readPacket() (packet *packets.StreamingPacket, err error) {
	lenPacketBytes, err := c.read(2)
	if err != nil {
		return nil, err
	}

	packet = packets.NewRawPacket()
	packet.AddData(lenPacketBytes)

	lenPacketBytes[0] = lenPacketBytes[0] ^ c.sessionRecvKey[0]
	lenPacketBytes[1] = lenPacketBytes[1] ^ c.sessionRecvKey[1]
	lenPacket := binary.BigEndian.Uint16(lenPacketBytes)

	rawPacket, err := c.read(lenPacket - 2)
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

	for remaining > 0 {
		n, err := c.conn.Read(data[offset:])
		if err != nil {
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
