package server

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/packets"
	"SmileVPN/server/users"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"time"
)

func (c *Client) handshakeStage1(initPassword [32]byte, users *users.Users) (err error) {
	c.logger.Info("Starting handshake stage 1 for client %s", c.addr)
	c.logger.Debug("Handshake stage 1: setting deadline to 15 seconds for client %s", c.addr)

	err = c.conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		c.logger.Error("Failed to set deadline for client %s: %v", c.addr, err)
		return err
	}
	c.sessionRecvKey.SetKey(initPassword[:])
	c.sessionSentKey.SetKey(initPassword[:])
	c.logger.Trace("Handshake stage 1: initial session keys set for client %s", c.addr)

	usernamePacket, err := c.readPacket()
	if err != nil {
		c.logger.Error("Failed to read username packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Trace("Handshake stage 1: username packet received from client %s, size=%d bytes", c.addr, len(usernamePacket.GetRawData()))

	err = usernamePacket.DecodeAndDecrypt(initPassword[:])
	if err != nil {
		c.logger.Error("Failed to decrypt username packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Debug("Handshake stage 1: username packet decrypted successfully for client %s", c.addr)

	timestampBytes, err := usernamePacket.GetSlicePlainData(16, 24)
	if err != nil {
		c.logger.Error("Failed to get timestamp from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	timestamp := binary.BigEndian.Uint64(timestampBytes)
	currentTime := time.Now().Unix()
	c.logger.Trace("Handshake stage 1: client timestamp=%d, server currentTime=%d", timestamp, currentTime)

	if timestamp > math.MaxInt64 {
		c.logger.Error("Timestamp overflow from client %s: %d", c.addr, timestamp)
		return fmt.Errorf("timestamp overflow")
	}
	timeDiff := currentTime - int64(timestamp)
	c.logger.Debug("Handshake stage 1: time difference=%d seconds for client %s", timeDiff, c.addr)

	if timeDiff > 5 {
		c.logger.Error("Invalid timestamp from client %s: diff=%d, current=%d, client=%d", c.addr, timeDiff, currentTime, timestamp)
		c.conn.Close()
		return fmt.Errorf("invalid timestamp")
	}
	c.logger.Trace("Handshake stage 1: timestamp validation passed for client %s", c.addr)

	username, err := usernamePacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Failed to get username from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}

	c.logger.Info("Client %s attempting authentication with username: %x", c.addr, username)
	c.logger.Debug("Handshake stage 1: looking up user for client %s", c.addr)

	user := users.GetUser([16]byte(username))
	if user == nil {
		c.logger.Error("User not found for client %s: username=%x", c.addr, username)
		c.conn.Close()
		return fmt.Errorf("user not found (username: %x)", username)
	}
	c.logger.Trace("Handshake stage 1: user found for client %s", c.addr)

	salt, err := crypto.RandomBytes(32)
	if err != nil {
		c.logger.Error("Failed to generate salt for client %s: %v", c.addr, err)
		return err
	}
	c.logger.Trace("Handshake stage 1: salt generated for client %s, size=%d bytes", c.addr, len(salt))

	saltPacket := packets.NewPlainPacket()
	saltPacket.AddData(salt)
	err = saltPacket.PackageAssembly(initPassword[:], false, false, false)
	if err != nil {
		c.logger.Error("Failed to package salt packet for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Debug("Handshake stage 1: salt packet assembled for client %s", c.addr)

	if _, err = c.conn.Write(saltPacket.GetRawData()); err != nil {
		c.logger.Error("Failed to send salt packet to client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Trace("Handshake stage 1: salt packet sent to client %s, size=%d bytes", c.addr, len(saltPacket.GetRawData()))

	password := user.GetPassword()
	firstSalt, err := saltPacket.GetSlicePlainData(0, 16)
	if err != nil {
		c.logger.Error("Failed to get first salt for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Trace("Handshake stage 1: first salt extracted for client %s", c.addr)

	c.sessionRecvKey.SetKey(password[:])
	c.sessionRecvKey.UpdateKey(firstSalt)
	c.logger.Debug("Handshake stage 1: session recv key derived for client %s", c.addr)

	secondSalt, err := saltPacket.GetSlicePlainData(16, 32)
	if err != nil {
		c.logger.Error("Failed to get second salt for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Trace("Handshake stage 1: second salt extracted for client %s", c.addr)

	c.sessionSentKey.SetKey(password[:])
	c.sessionSentKey.UpdateKey(secondSalt)
	c.logger.Debug("Handshake stage 1: session sent key derived for client %s", c.addr)

	c.logger.Info("Handshake stage 1 completed for client %s", c.addr)
	return nil
}

func (c *Client) handshakeStage2(clientIP *net.IP) (err error) {
	c.logger.Info("Starting handshake stage 2 for client %s, assigned IP: %s", c.addr, clientIP.String())
	c.logger.Debug("Handshake stage 2: waiting for confirmation packet from client %s", c.addr)

	packet, err := c.readPacket()
	if err != nil {
		c.logger.Error("Failed to read stage 2 packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Trace("Handshake stage 2: packet received from client %s, size=%d bytes", c.addr, len(packet.GetRawData()))

	err = packet.DecodeAndDecrypt(c.sessionRecvKey.GetBytes())
	if err != nil {
		c.logger.Error("Failed to decrypt stage 2 packet from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Debug("Handshake stage 2: packet decrypted successfully for client %s", c.addr)

	confirmationByte, err := packet.GetSlicePlainData(0, 1)
	if err != nil {
		c.logger.Error("Failed to get confirmation byte from client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Trace("Handshake stage 2: confirmation byte=0x%02X from client %s", confirmationByte[0], c.addr)

	if confirmationByte[0] != 0xFF {
		c.logger.Error("Client %s rejected the connection (confirmation byte: %x)", c.addr, confirmationByte[0])
		c.conn.Close()
		return fmt.Errorf("the client rejected the connection")
	}

	c.logger.Info("Client %s confirmed connection", c.addr)
	c.logger.Debug("Handshake stage 2: starting ECDH key exchange for client %s", c.addr)

	curve := ecdh.X25519()
	c.logger.Trace("Handshake stage 2: using X25519 curve for client %s", c.addr)

	publicClientKey, err := curve.NewPublicKey(packet.GetPublicKey())
	if err != nil {
		c.logger.Error("Failed to parse client's public key for %s: %v", c.addr, err)
		return err
	}
	c.logger.Debug("Handshake stage 2: client public key parsed for %s", c.addr)

	privateServerKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		c.logger.Error("Failed to generate server private key for %s: %v", c.addr, err)
		return err
	}
	c.logger.Trace("Handshake stage 2: server key pair generated for client %s", c.addr)

	publicServerKey := privateServerKey.PublicKey()
	c.logger.Debug("Handshake stage 2: server public key prepared for client %s", c.addr)

	ipPacket := packets.NewPlainPacket()
	ipPacket.AddData(clientIP.To4())
	c.logger.Trace("Handshake stage 2: IP %s added to packet for client %s", clientIP.String(), c.addr)

	ipPacket.AddParameter("publicKey", publicServerKey.Bytes())
	err = ipPacket.PackageAssembly(c.sessionSentKey.GetBytes(), false, true, false)
	if err != nil {
		c.logger.Error("Failed to package IP packet for client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Debug("Handshake stage 2: IP packet assembled with ECDH flag for client %s", c.addr)

	if _, err = c.conn.Write(ipPacket.GetRawData()); err != nil {
		c.logger.Error("Failed to send IP assignment to client %s: %v", c.addr, err)
		c.conn.Close()
		return err
	}
	c.logger.Trace("Handshake stage 2: IP packet sent to client %s, size=%d bytes", c.addr, len(ipPacket.GetRawData()))

	c.localIP = clientIP
	c.logger.Info("Assigned IP %s to client %s", clientIP.String(), c.addr)

	secret, err := privateServerKey.ECDH(publicClientKey)
	if err != nil {
		c.logger.Error("Failed to compute shared secret for client %s: %v", c.addr, err)
		return err
	}
	c.logger.Debug("Handshake stage 2: shared secret computed for client %s", c.addr)

	c.computeNextSessionRecvKey(secret)
	c.computeNextSessionSentKey(secret)
	c.logger.Trace("Handshake stage 2: session keys updated with ECDH secret for client %s", c.addr)

	c.logger.Info("Handshake stage 2 completed for client %s", c.addr)
	return nil
}
