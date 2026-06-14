package server

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/logger"
	"SmileVPN/internal/packets"
	"SmileVPN/server/users"
	"crypto/ecdh"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type Client struct {
	addr                      string
	conn                      *net.TCPConn
	user                      *users.User //nolint:unus
	countRecv                 atomic.Uint32
	countSent                 atomic.Uint32
	countRecvBytes            atomic.Uint32
	countSentBytes            atomic.Uint32
	sessionSentKey            *crypto.Key
	sessionRecvKey            *crypto.Key
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
	c.sessionRecvKey.UpdateKey(salt)
}

func (c *Client) computeNextSessionSentKey(salt []byte) {
	c.sessionSentKey.UpdateKey(salt)
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

func (c *Client) Close() {
	c.conn.Close()
}
