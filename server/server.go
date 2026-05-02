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

	s.logger.Info("Starting the server")
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("Server startup error: %v", err)
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
		s.logger.Error("Error create tunnel: %v", err)
		return err
	}

	s.tunnel = tun.(*tunnel.LinuxTunnel)

	err = s.tunnel.Up([]string{})
	if err != nil {
		return err
	}

	s.logger.Info("Starting the main VPN operation cycle")

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

			s.logger.Info("New connection from %s", conn.RemoteAddr().String())

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

	clientAddr := connTCP.RemoteAddr().String()

	s.logger.Info("The handshake process with client %s has begun", clientAddr)
	err := client.handshakeStage1(s.config.InitPassword, s.users)
	if err != nil {
		s.logger.Error("Error during the first stage of the handshake with client %s: %v", clientAddr, err)
		return
	}

	clientIP := s.ipPool.AcquireIP()
	err = client.handshakeStage2(&clientIP)
	if err != nil {
		s.logger.Error("Error during the second stage of the handshake with client %s: %v", clientAddr, err)
		s.ipPool.ReleaseIP(clientIP)
		return
	}
	s.logger.Info("The handshake process with client %s is complete", clientAddr)

	s.clients[clientIP.String()] = client

	err = conn.SetDeadline(time.Time{})
	if err != nil {
		s.logger.Error("Error setting the deadline for client %s: %v", clientAddr, err)
		return
	}

	go s.handleClient(client)
}

func (s *Server) tunnelReader() {
	s.logger.Info("Tunnel reader started")
	for {
		rawPacket := make([]byte, 65535)
		n, err := s.tunnel.Read(rawPacket)
		if err != nil {
			s.logger.Error("Tunnel read error: %v", err)
			continue
		}
		rawPacket = rawPacket[:n]
		if n < 20 {
			continue
		}

		dstIP := rawPacket[16:20]
		ipStr := fmt.Sprintf("%d.%d.%d.%d", dstIP[0], dstIP[1], dstIP[2], dstIP[3])

		s.mu.Lock()
		client, ok := s.clients[ipStr]
		s.mu.Unlock()
		if !ok {
			continue
		}

		if client.roundECDHLock != nil {
			<-client.roundECDHLock
		}

		salt, err := crypto.RandomBytes(8)
		if err != nil {
			s.logger.Error("Failed to generate salt for client %s: %v", client.addr, err)
			continue
		}

		packet := packets.NewPlainPacket()
		packet.AddData(rawPacket)

		needsECDH := client.countSent >= uint32(math.Pow(2, 16)) || time.Since(client.lastRoundECDH) >= 4*time.Minute
		if needsECDH {
			s.logger.Debug("Initiating ECDH rekey for client %s (countSent=%d, lastRoundECDH=%v)",
				client.addr, client.countSent, time.Since(client.lastRoundECDH))

			curve := ecdh.X25519()
			privateKey, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				s.logger.Error("Failed to generate ephemeral key for client %s: %v", client.addr, err)
				return
			}

			client.ephemeralPrivateServerKey = privateKey
			err = packet.PackageAssembly(client.sessionSentKey, salt, privateKey.PublicKey().Bytes(), false, true)
			if err != nil {
				s.logger.Error("Failed to package packet with ECDH for client %s: %v", client.addr, err)
				continue
			}
		} else {
			err = packet.PackageAssembly(client.sessionSentKey, salt, []byte{}, false, false)
			if err != nil {
				s.logger.Error("Failed to package packet for client %s: %v", client.addr, err)
				continue
			}
		}

		_, err = client.conn.Write(packet.GetRawData())
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				s.logger.Info("Client %s connection closed, releasing IP %s", client.addr, client.localIP.String())
				s.ipPool.ReleaseIP(*client.localIP)
				delete(s.clients, client.localIP.String())
				continue
			}
			s.logger.Error("Failed to write packet to client %s: %v", client.addr, err)
			continue
		}

		if packet.GetEcdhFlag() {
			s.logger.Debug("ECDH flag set for client %s, creating lock", client.addr)
			client.roundECDHLock = make(chan struct{}, 1)
		}

		client.computeNextSessionSentKey(salt)
		client.countSent++
	}
}

func (s *Server) handleClient(client *Client) {
	s.logger.Info("Starting to handle client %s (IP: %s)", client.addr, client.localIP.String())
	defer func() {
		s.logger.Info("Stopping to handle client %s (IP: %s)", client.addr, client.localIP.String())
		client.conn.Close()
	}()

	for {
		select {
		case <-s.stopCh:
			s.logger.Info("Stop signal received, stopping handler for client %s", client.addr)
			return
		default:
			packet, err := client.readPacket()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					s.logger.Info("Client %s connection closed (net.ErrClosed), releasing IP %s", client.addr, client.localIP.String())
					s.ipPool.ReleaseIP(*client.localIP)
					delete(s.clients, client.localIP.String())
					return
				}

				if err.Error() == "EOF" {
					s.logger.Info("Client %s disconnected (EOF), releasing IP %s", client.addr, client.localIP.String())
					s.ipPool.ReleaseIP(*client.localIP)
					delete(s.clients, client.localIP.String())
					return
				}
				s.logger.Error("Failed to read packet from client %s: %v", client.addr, err)
				continue
			}

			err = packet.DecodeAndDecrypt(client.sessionRecvKey, true)
			if err != nil {
				s.logger.Error("Failed to decrypt packet from client %s: %v", client.addr, err)
				continue
			}

			client.countRecv++
			client.computeNextSessionRecvKey(packet.GetSalt())

			if packet.GetEcdhFlag() && client.ephemeralPrivateServerKey != nil {
				s.logger.Debug("Processing ECDH rekey from client %s", client.addr)

				curve := ecdh.X25519()
				clientPublicKey, err := curve.NewPublicKey(packet.GetPublicKey())
				if err != nil {
					s.logger.Error("Failed to parse client public key for %s: %v", client.addr, err)
					return
				}

				secret, err := client.ephemeralPrivateServerKey.ECDH(clientPublicKey)
				if err != nil {
					s.logger.Error("Failed to compute shared secret for client %s: %v", client.addr, err)
					return
				}
				client.ephemeralPrivateServerKey = nil
				client.lastRoundECDH = time.Now()

				client.countRecv = 0
				client.countSent = 0

				client.computeNextSessionSentKey(secret)
				client.computeNextSessionRecvKey(secret)
				close(client.roundECDHLock)

				s.logger.Info("ECDH rekey completed for client %s", client.addr)
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
				s.logger.Error("Failed to get source IP from packet for client %s: %v", client.addr, err)
				continue
			}

			srcIP := fmt.Sprintf("%d.%d.%d.%d", ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3])
			if srcIP != client.localIP.String() {
				continue
			}

			_, err = s.tunnel.Write(packet.GetPlainData())
			if err != nil {
				s.logger.Error("Failed to write packet to tunnel for client %s: %v", client.addr, err)
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
