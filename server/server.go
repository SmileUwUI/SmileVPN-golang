package server

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/logger"
	"SmileVPN/internal/packets"
	"SmileVPN/internal/tunnel"
	"SmileVPN/server/config"
	"SmileVPN/server/users"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"math"
	"net"
	"sync"
	"time"
)

type Server struct {
	config      *config.Config
	users       *users.Users
	ipPool      *IPPool
	listener    net.Listener
	wg          sync.WaitGroup
	clientCount int32
	clients     map[string]*Client
	logger      *logger.Logger
	tunnel      *tunnel.LinuxTunnel

	stopCh chan struct{}
	mu     sync.RWMutex
}

func NewServer(cfg *config.Config, usersDB *users.Users, logger *logger.Logger) (server *Server, err error) {
	ippool, err := NewIPPool("10.8.83.0/24")
	if err != nil {
		return nil, fmt.Errorf("error creating ip pool: %v", err)
	}

	return &Server{
		config:  cfg,
		users:   usersDB,
		ipPool:  ippool,
		clients: make(map[string]*Client),
		stopCh:  make(chan struct{}),
		logger:  logger,
	}, nil
}

func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Host, s.config.Port)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to start TCP server: %w", err)
	}

	s.listener = listener

	tun, err := tunnel.NewLinuxTunnel(
		"tun0",
		1500,
		net.ParseIP("10.8.83.1"),
		net.IPv4Mask(255, 255, 255, 0),
	)

	if err != nil {
		return err
	}

	s.tunnel = tun.(*tunnel.LinuxTunnel)

	err = s.tunnel.Up([]string{})
	if err != nil {
		return err
	}

	go s.acceptConnections()

	go s.tunnelReader()

	go s.cleanupIdleClients()

	return nil
}

func (s *Server) acceptConnections() {
	for {
		select {
		case <-s.stopCh:
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					continue
				}
			}

			s.mu.RLock()
			clientCount := int(s.clientCount)
			maxClients := s.config.MaxClients
			s.mu.RUnlock()

			if clientCount >= maxClients {
				conn.Close()
				continue
			}

			s.wg.Add(1)
			s.incrementClientCount()

			go s.handleConnection(conn)
		}
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		s.wg.Done()
		s.decrementClientCount()
	}()

	connTCP := conn.(*net.TCPConn)

	now := time.Now()

	client := &Client{
		addr:            conn.RemoteAddr().String(),
		conn:            connTCP,
		countRecv:       0,
		countSent:       0,
		countRecvBytes:  0,
		countSentBytes:  0,
		sessionRecvKey:  []byte{},
		sessionSentKey:  []byte{},
		createdAt:       now,
		lastActive:      now,
		lastRoundECDH:   now,
		logger:          s.logger,
		maxPacketLength: 4096,
	}

	err := client.handshakeStage1(s.config.InitPassword, s.users)
	if err != nil {
		return
	}

	clientIP := s.ipPool.AcquireIP()
	err = client.handshakeStage2(&clientIP)
	if err != nil {
		s.ipPool.ReleaseIP(clientIP)
		return
	}

	s.clients[clientIP.String()] = client

	err = conn.SetDeadline(time.Time{})
	if err != nil {
		return
	}

	go s.handleClient(client)
}

func (s *Server) tunnelReader() {
	for {
		rawPacket := make([]byte, 65535)
		n, err := s.tunnel.Read(rawPacket)
		if err != nil {
			continue
		}
		rawPacket = rawPacket[:n]
		if n < 20 {
			continue
		}

		dstIP := rawPacket[16:20]

		s.mu.Lock()
		client, ok := s.clients[fmt.Sprintf("%d.%d.%d.%d", dstIP[0], dstIP[1], dstIP[2], dstIP[3])]
		s.mu.Unlock()
		if !ok {
			continue
		}

		if client.roundECDHLock != nil {
			<-client.roundECDHLock
		}

		salt, err := crypto.RandomBytes(8)
		if err != nil {
			continue
		}

		packet := packets.NewPlainPacket()
		packet.AddData(rawPacket)

		if client.countSent >= uint32(math.Pow(2, 16)) || time.Since(client.lastRoundECDH) >= 4*time.Minute {
			curve := ecdh.X25519()
			privateKey, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				return
			}

			client.ephemeralPrivateServerKey = privateKey
			err = packet.PackageAssembly(client.sessionSentKey, salt, privateKey.PublicKey().Bytes(), false, true)

			if err != nil {
				continue
			}
		} else {
			err = packet.PackageAssembly(client.sessionSentKey, salt, []byte{}, false, false)

			if err != nil {
				continue
			}
		}

		_, err = client.conn.Write(packet.GetRawData())
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.ipPool.ReleaseIP(*client.localIP)
				delete(s.clients, client.localIP.String())
				continue
			}
			continue
		}

		if packet.GetEcdhFlag() {
			client.roundECDHLock = make(chan struct{}, 1)
		}

		client.computeNextSessionSentKey(salt)
		client.countSent++
	}
}

func (s *Server) handleClient(client *Client) {
	defer client.conn.Close()

	for {
		select {
		case <-s.stopCh:
			return
		default:
			packet, err := client.readPacket()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					s.ipPool.ReleaseIP(*client.localIP)
					delete(s.clients, client.localIP.String())
					return
				}

				if err.Error() == "EOF" {
					s.ipPool.ReleaseIP(*client.localIP)
					delete(s.clients, client.localIP.String())
					return
				}
				continue
			}
			err = packet.DecodeAndDecrypt(client.sessionRecvKey, true)

			if err != nil {
				continue
			}

			client.countRecv++
			client.computeNextSessionRecvKey(packet.GetSalt())

			if packet.GetEcdhFlag() && client.ephemeralPrivateServerKey != nil {
				curve := ecdh.X25519()
				clientPublicKey, err := curve.NewPublicKey(packet.GetPublicKey())
				if err != nil {
					return
				}

				secret, err := client.ephemeralPrivateServerKey.ECDH(clientPublicKey)
				if err != nil {
					return
				}
				client.ephemeralPrivateServerKey = nil
				client.lastRoundECDH = time.Now()

				client.countRecv = 0
				client.countSent = 0

				client.computeNextSessionSentKey(secret)
				client.computeNextSessionRecvKey(secret)
				close(client.roundECDHLock)
			}

			client.mu.Lock()
			client.lastActive = time.Now()

			countRecv := len(packet.GetRawData())
			if countRecv < 0 {
				countRecv = 0
			}

			client.countRecvBytes += uint32(countRecv)
			client.mu.Unlock()

			ipSrc, err := packet.GetSlicePlainData(12, 16)
			if err != nil {
				continue
			}
			if fmt.Sprintf("%d.%d.%d.%d", ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3]) != client.localIP.String() {
				continue
			}

			_, err = s.tunnel.Write(packet.GetPlainData())
			if err != nil {
				continue
			}
		}
	}
}

func (s *Server) cleanupIdleClients() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:

			s.mu.Lock()
			idleCount := 0
			for addr, client := range s.clients {
				idleTime := time.Since(client.lastActive)
				if idleTime > 10*time.Minute {
					client.conn.Close()
					s.ipPool.ReleaseIP(*client.localIP)
					delete(s.clients, addr)
					idleCount++
				}
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) incrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount++
}

func (s *Server) decrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount--
}

func (s *Server) GetClientCount() int32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientCount
}
