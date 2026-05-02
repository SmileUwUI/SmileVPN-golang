package server

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/packets"
	"SmileVPN/server/users"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

func (c *Client) handshakeStage1(initPassword [32]byte, users *users.Users) (err error) {
	c.logger.Info("Starting handshake stage 1 for client %s", c.addr)

	err = c.conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		c.logger.Error("Failed to set deadline for client %s: %v", c.addr, err)
		return err
	}
	c.sessionRecvKey = initPassword[:]
	c.sessionSentKey = initPassword[:]

	usernamePacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Failed to read username packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	err = usernamePacket.DecodeAndDecrypt(initPassword[:], false)
	if err != nil {
		c.logger.Error("Failed to decrypt username packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	timestampBytes, err := usernamePacket.GetSlicePlainData(16, 24)
	if err != nil {
		c.logger.Error("Failed to get timestamp from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	timestamp := binary.BigEndian.Uint64(timestampBytes)
	currentTime := time.Now().Unix()
	if timestamp > math.MaxInt64 {
		c.logger.Error("Timestamp overflow from client %s: %d", c.addr, timestamp)
		return fmt.Errorf("timestamp overflow")
	}
	timeDiff := currentTime - int64(timestamp)

	if timeDiff > 5 {
		c.logger.Error("Invalid timestamp from client %s: diff=%d, current=%d, client=%d", c.addr, timeDiff, currentTime, timestamp)
		c.conn.Close()
		return fmt.Errorf("invalid timestamp")
	}

	username, err := usernamePacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Failed to get username from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	c.logger.Info("Client %s attempting authentication with username: %x", c.addr, username)

	user := users.GetUser([16]byte(username))
	if user == nil {
		c.logger.Error("User not found for client %s: username=%x", c.addr, username)
		c.conn.Close()
		return fmt.Errorf("user not found (username: %x)", username)
	}

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		c.logger.Error("Failed to generate salt for client %s: %v", c.addr, err)
		return err
	}

	saltPacket := packets.NewPlainPacket()
	saltPacket.AddData(salt)
	err = saltPacket.PackageAssembly(initPassword[:], []byte{}, []byte{}, false, false)
	if err != nil {
		c.logger.Error("Failed to package salt packet for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	if _, err = c.conn.Write(saltPacket.GetRawData()); err != nil {
		c.logger.Error("Failed to send salt packet to client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	sessionRecvKeyHasher := sha256.New()
	password := user.GetPassword()
	firstSalt, err := saltPacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Failed to get first salt for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	sessionRecvKeyHasher.Write(password[:])
	sessionRecvKeyHasher.Write([]byte(":"))
	sessionRecvKeyHasher.Write(firstSalt)
	c.sessionRecvKey = sessionRecvKeyHasher.Sum(nil)

	sessionSentKeyHasher := sha256.New()
	secondSalt, err := saltPacket.GetSlicePlainData(16, 32)
	if err != nil {
		c.logger.Error("Failed to get second salt for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	sessionSentKeyHasher.Write(password[:])
	sessionSentKeyHasher.Write([]byte(":"))
	sessionSentKeyHasher.Write(secondSalt)
	c.sessionSentKey = sessionSentKeyHasher.Sum(nil)

	c.logger.Info("Handshake stage 1 completed for client %s", c.addr)
	return nil
}

func (c *Client) handshakeStage2(clientIP *net.IP) (err error) {
	c.logger.Info("Starting handshake stage 2 for client %s, assigned IP: %s", c.addr, clientIP.String())

	packet, err := c.readPacket()
	if err != nil {
		c.logger.Error("Failed to read stage 2 packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	err = packet.DecodeAndDecrypt(c.sessionRecvKey, false)
	if err != nil {
		c.logger.Error("Failed to decrypt stage 2 packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	confirmationByte, err := packet.GetSlicePlainData(0, 1)
	if err != nil {
		c.logger.Error("Failed to get confirmation byte from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	if confirmationByte[0] != 0xFF {
		c.logger.Error("Client %s rejected the connection (confirmation byte: %x)", c.addr, confirmationByte[0])
		c.conn.Close()
		return fmt.Errorf("the client rejected the connection")
	}

	c.logger.Info("Client %s confirmed connection", c.addr)

	curve := ecdh.X25519()

	publicClientKey, err := curve.NewPublicKey(packet.GetPublicKey())
	if err != nil {
		c.logger.Error("Failed to parse client's public key for %s: %v", c.addr, err)
		return err
	}

	privateServerKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		c.logger.Error("Failed to generate server private key for %s: %v", c.addr, err)
		return err
	}

	publicServerKey := privateServerKey.PublicKey()

	ipPacket := packets.NewPlainPacket()
	ipPacket.AddData(clientIP.To4())
	err = ipPacket.PackageAssembly(c.sessionSentKey, []byte{}, publicServerKey.Bytes(), false, true)
	if err != nil {
		c.logger.Error("Failed to package IP packet for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	if _, err = c.conn.Write(ipPacket.GetRawData()); err != nil {
		c.logger.Error("Failed to send IP assignment to client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	c.localIP = clientIP
	c.logger.Info("Assigned IP %s to client %s", clientIP.String(), c.addr)

	secret, err := privateServerKey.ECDH(publicClientKey)
	if err != nil {
		c.logger.Error("Failed to compute shared secret for client %s: %v", c.addr, err)
		return err
	}
	c.computeNextSessionRecvKey(secret)
	c.computeNextSessionSentKey(secret)

	c.logger.Info("Handshake stage 2 completed for client %s", c.addr)
	return nil
}
