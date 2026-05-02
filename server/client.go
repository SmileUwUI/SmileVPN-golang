package server

import (
	"SmileVPN/internal/logger"
	"SmileVPN/internal/packets"
	"SmileVPN/server/users"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type Client struct {
	addr                      string
	conn                      *net.TCPConn
	user                      *users.User //nolint:unus
	countRecv                 uint32
	countSent                 uint32
	countRecvBytes            uint32
	countSentBytes            uint32
	sessionSentKey            []byte
	sessionRecvKey            []byte
	createdAt                 time.Time
	lastActive                time.Time
	lastRoundECDH             time.Time
	roundECDHLock             chan struct{}
	ephemeralPrivateServerKey *ecdh.PrivateKey
	logger                    *logger.Logger
	maxPacketLength           uint16
	localIP                   *net.IP
	mu                        sync.RWMutex
}

func (c *Client) computeNextSessionRecvKey(salt []byte) {
	hasher := sha256.New()
	hasher.Write(c.sessionRecvKey)
	hasher.Write([]byte(":"))
	hasher.Write(salt)

	c.sessionRecvKey = hasher.Sum(nil)
}

func (c *Client) computeNextSessionSentKey(salt []byte) {
	hasher := sha256.New()
	hasher.Write(c.sessionSentKey)
	hasher.Write([]byte(":"))
	hasher.Write(salt)

	c.sessionSentKey = hasher.Sum(nil)
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
