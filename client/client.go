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

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		c.logger.Error("Failed to connect to server: %v", err)
		return fmt.Errorf("failed to connect to server: %w", err)
	}
	c.logger.Trace("The connection was established successfully")

	c.conn = conn.(*net.TCPConn)

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

	c.logger.Trace("Assembly a packet with a username")
	err = packet.PackageAssembly(c.initPassword[:], []byte{}, []byte{}, false, false)
	if err != nil {
		c.logger.Error("An error occurred while creating the packet with the username: %v", err)
		return err
	}

	c.logger.Trace("Sending a packet containing username")
	if _, err = c.conn.Write(packet.GetRawData()); err != nil {
		c.logger.Error("Error sending a packet with username: %v", err)
		return err
	}

	c.logger.Trace("Reading the salt packet")
	saltPacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Error reading the salt packet: %v", err)
		return err
	}

	c.logger.Trace("Packet decoding and decryption")
	err = saltPacket.DecodeAndDecrypt(c.initPassword[:], false)
	if err != nil {
		c.logger.Error("Error decoding and decrypting a salted packet: %v", err)
		return err
	}

	firstSalt, err := saltPacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Error when attempting to retrieve the first salt: %v", err)
		return fmt.Errorf("error when attempting to retrieve the first salt: %v", err)
	}

	secondSalt, err := saltPacket.GetSlicePlainData(16, 32)
	if err != nil {
		c.logger.Error("Error when attempting to retrieve the second salt: %v", err)
		return fmt.Errorf("error when attempting to retrieve the second salt: %v", err)
	}

	c.logger.Trace("Calculating the send key")
	c.hasher.Reset()
	c.hasher.Write(c.password[:])
	c.hasher.Write([]byte(":"))
	c.hasher.Write(firstSalt)
	c.sessionSentKey = c.hasher.Sum(nil)

	c.logger.Trace("Calculating the recv key")
	c.hasher.Reset()
	c.hasher.Write(c.password[:])
	c.hasher.Write([]byte(":"))
	c.hasher.Write(secondSalt)
	c.sessionRecvKey = c.hasher.Sum(nil)

	okPacket := packets.NewPlainPacket()
	okPacket.AddData([]byte{0xFF})

	curve := ecdh.X25519()
	c.logger.Debug("Generating a keypair for ECDH")
	privateClientKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		c.logger.Error("Error generating the keypair")
		return err
	}
	publicClientKey := privateClientKey.PublicKey()

	c.logger.Trace("Assembly the packet with connection establishment confirmation ")
	err = okPacket.PackageAssembly(c.sessionSentKey, []byte{}, publicClientKey.Bytes(), false, true)
	if err != nil {
		c.logger.Error("Error assembly a packet to confirm the connection setup: %v", err)
		return err
	}

	c.logger.Trace("Sending a packet confirming that the connection has been established ")
	if _, err = c.conn.Write(okPacket.GetRawData()); err != nil {
		c.logger.Error("Error sending the connection establishment acknowledgment packet: %v", err)
		return err
	}

	ipPacket, err := c.readPacket()
	c.logger.Trace("Reading a packet containing an IP address ")
	if err != nil {
		c.logger.Error("Error reading the packet with IP address: %v", err)
		if err.Error() == "EOF" {
			return err
		}
		return err
	}

	err = ipPacket.DecodeAndDecrypt(c.sessionRecvKey, false)
	if err != nil {
		c.logger.Error("Error decoding and decrypting a packet containing the server's IP address and public key: %v", err)
		return err
	}

	ipBytes, err := ipPacket.GetSlicePlainData(0, 4)
	if err != nil {
		c.logger.Error("Error when attempting to retrieve the IP address: %v", err)
		return fmt.Errorf("error when attempting to retrieve the IP address: %v", err)
	}

	c.logger.Debug("Parsing the server's public key")
	publicServerKey, err := curve.NewPublicKey(ipPacket.GetPublicKey())
	if err != nil {
		c.logger.Error("Error parsing the server's public key: %v", err)
		return err
	}

	c.logger.Debug("Conducting the ECDH")
	secret, err := privateClientKey.ECDH(publicServerKey)
	if err != nil {
		c.logger.Error("ECDH execution error: %v", err)
		return err
	}
	c.computeNextSessionRecvKey(secret)
	c.computeNextSessionSentKey(secret)

	c.logger.Debug("Creating a TUN interface")
	tun, err := tunnel.NewTunnel(
		"smile-tun0",
		1500,
		net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3])),
		net.IPv4Mask(255, 255, 255, 0),
	)

	if err != nil {
		c.logger.Error("Failed to create tunnel: %v", err)
		return fmt.Errorf("error create tunnel: %v", err)
	}

	c.tunnel = &tun

	c.wg.Add(3)
	go c.readerTunnel()
	c.logger.Debug("Launch the goroutine to read the tunnel")

	go c.writerTunnel()
	c.logger.Debug("A daemon has been launched to read packets from the server and write them to the tunnel")

	go c.sender()
	c.logger.Debug("Launched a goroutine to send packets to the server.")

	return nil
}

func (c *Client) Stop() {
	close(c.stopCh)
	c.logger.Debug("Wait for all goroutines to complete")
	c.wg.Wait()
	c.logger.Debug("All goroutines are complete")
	c.logger.Debug("Close tunnel")
	err := (*c.tunnel).Close()
	if err != nil {
		c.logger.Error("An error occurred while closing the tunnel: %v", err)
	}
}

func (c *Client) writerTunnel() {
	defer c.wg.Done()
	var secret []byte
	for {
		select {
		case <-c.stopCh:
			return
		default:
			c.logger.Trace("Reading a packet from socket #%d", c.countRecv)
			packet, err := c.readPacket()
			if err != nil {
				c.logger.Error("Failed to read packet: %v", err)
				if err.Error() == "EOF" {
					c.Stop()
					return
				}
				continue
			}
			c.countRecv++

			err = packet.DecodeAndDecrypt(c.sessionRecvKey, true)
			if err != nil {
				c.logger.Error("Failed to decrypt packet: %v", err)
				continue
			}

			c.logger.Trace("Send packet #%d through the tunnel", c.countRecv)
			_, err = (*c.tunnel).Write(packet.GetPlainData())
			if err != nil {
				c.logger.Error("Failed to write packet in tun: %v", err)
			}

			c.computeNextSessionRecvKey(packet.GetSalt())

			if packet.GetEcdhFlag() {
				c.logger.Debug("A new round of the ECDH has begun")

				var publicServerKey *ecdh.PublicKey
				curve := ecdh.X25519()
				publicServerKey, err = curve.NewPublicKey(packet.GetPublicKey())
				if err != nil {
					c.logger.Error("Error parsing the server's public key: %v", err)
					continue
				}

				privateKey, err := curve.GenerateKey(rand.Reader)
				if err != nil {
					c.logger.Error("Error generating the keypair: %v", err)
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
		c.logger.Error("Failed to bring TUN interface up: %v", err)
		return
	}
	defer func() {
		err := (*c.tunnel).Down()
		if err != nil {
			c.logger.Error("Error setting the tunnel to DOWN status: %v", err)
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
				c.logger.Error("Failed to read from tunnel: %v", err)
				return
			}
			c.logger.Trace("Read packet from tunnel #%d", c.countSent)
			c.countSent++

			packet := packets.NewPlainPacket()

			salt, err := crypto.RandomBytes(8)
			if err != nil {
				c.logger.Error("Error generating random bytes: %v", err)
			}

			packet.AddData(rawPacket[:n])
			if c.ephemeralPublicClientKey != nil {
				err = packet.PackageAssembly(c.sessionSentKey, salt, c.ephemeralPublicClientKey.Bytes(), false, true)
				c.ephemeralPublicClientKey = nil
			} else {
				err = packet.PackageAssembly(c.sessionSentKey, salt, []byte{}, false, false)
			}
			if err != nil {
				c.logger.Error("Error while building the package: %v", err)
				continue
			}

			c.logger.Trace("Sending a packet to server number #%d", c.countSent)
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
					c.logger.Error("Error while writing: %v", err)
				}
			}
			c.packetBuffer = []*packets.StreamingPacket{}
			n, err := rand.Int(rand.Reader, big.NewInt(4))
			if err != nil {
				c.logger.Error("Error generating a random batch size: %v", err)
			}

			c.sizeBatch = int(n.Int64()) + 1
			c.logger.Trace("Next size of batch: %d", c.sizeBatch)
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
