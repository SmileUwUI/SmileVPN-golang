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
	logger.Trace("Creating new server instance")

	ippool, err := NewIPPool("10.8.83.0/24")
	if err != nil {
		logger.Error("Failed to create IP pool: %v", err)
		return nil, fmt.Errorf("error creating ip pool: %v", err)
	}
	logger.Debug("IP pool created with subnet 10.8.83.0/24")

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
	s.logger.Debug("Server configuration: host=%s, port=%d, maxClients=%d", s.config.Host, s.config.Port, s.config.MaxClients)

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		s.logger.Error("Server startup error: %v", err)
		return fmt.Errorf("failed to start TCP server: %w", err)
	}

	s.listener = listener
	s.logger.Debug("TCP listener created on %s", addr)

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
	s.logger.Debug("Tunnel interface tun0 created with MTU=1500, IP=10.8.83.1/24")

	err = s.tunnel.Up([]string{}, false)
	if err != nil {
		s.logger.Error("Failed to bring tunnel up: %v", err)
		return err
	}
	s.logger.Info("Tunnel interface is up")

	s.logger.Info("Starting the main VPN operation cycle")
	s.logger.Debug("Launching goroutines: acceptConnections, tunnelReader, cleanupIdleClients")

	go s.acceptConnections()
	go s.tunnelReader()
	go s.cleanupIdleClients()

	return nil
}

func (s *Server) acceptConnections() {
	s.logger.Debug("Accept connections goroutine started")

	for {
		select {
		case <-s.stopCh:
			s.logger.Debug("Accept connections received stop signal, exiting")
			return
		default:
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					s.logger.Error("Accept error: %v", err)
					continue
				}
			}

			s.mu.RLock()
			clientCount := int(s.clientCount)
			maxClients := s.config.MaxClients
			s.mu.RUnlock()

			if clientCount >= maxClients {
				s.logger.Error("Maximum clients reached (%d), rejecting connection from %s", maxClients, conn.RemoteAddr().String())
				conn.Close()
				continue
			}

			s.logger.Info("New connection from %s (active clients: %d/%d)", conn.RemoteAddr().String(), clientCount+1, maxClients)

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
	clientAddr := connTCP.RemoteAddr().String()
	s.logger.Trace("Handling new connection from %s", clientAddr)

	now := time.Now()

	client := &Client{
		addr:            clientAddr,
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

	s.logger.Info("The handshake process with client %s has begun", clientAddr)
	s.logger.Debug("Starting handshake stage 1 for client %s", clientAddr)

	err := client.handshakeStage1(s.config.InitPassword, s.users)
	if err != nil {
		s.logger.Error("Error during the first stage of the handshake with client %s: %v", clientAddr, err)
		return
	}
	s.logger.Debug("Handshake stage 1 completed for client %s", clientAddr)

	clientIP := s.ipPool.AcquireIP()
	s.logger.Debug("IP %s acquired from pool for client %s", clientIP.String(), clientAddr)

	err = client.handshakeStage2(&clientIP)
	if err != nil {
		s.logger.Error("Error during the second stage of the handshake with client %s: %v", clientAddr, err)
		s.ipPool.ReleaseIP(clientIP)
		s.logger.Debug("IP %s released back to pool for client %s", clientIP.String(), clientAddr)
		return
	}
	s.logger.Info("The handshake process with client %s is complete", clientAddr)

	s.mu.Lock()
	s.clients[clientIP.String()] = client
	s.mu.Unlock()
	s.logger.Debug("Client %s added to clients map with IP %s", clientAddr, clientIP.String())

	err = conn.SetDeadline(time.Time{})
	if err != nil {
		s.logger.Error("Error setting the deadline for client %s: %v", clientAddr, err)
		return
	}
	s.logger.Trace("Deadline cleared for client %s", clientAddr)

	go s.handleClient(client)
}

func (s *Server) tunnelReader() {
	s.logger.Info("Tunnel reader started")
	s.logger.Debug("Tunnel reader goroutine: entering main loop")

	for {
		rawPacket := make([]byte, 65535)
		n, err := s.tunnel.Read(rawPacket)
		if err != nil {
			s.logger.Error("Tunnel read error: %v", err)
			continue
		}
		rawPacket = rawPacket[:n]

		if n < 20 {
			s.logger.Trace("Packet too short: %d bytes (minimum 20), skipping", n)
			continue
		}
		s.logger.Trace("Read %d bytes from tunnel", n)

		dstIP := rawPacket[16:20]
		ipStr := fmt.Sprintf("%d.%d.%d.%d", dstIP[0], dstIP[1], dstIP[2], dstIP[3])
		s.logger.Trace("Packet destination IP: %s", ipStr)

		s.mu.Lock()
		client, ok := s.clients[ipStr]
		s.mu.Unlock()
		if !ok {
			s.logger.Debug("No client found for destination IP: %s", ipStr)
			continue
		}

		if client.roundECDHLock != nil {
			s.logger.Trace("Waiting for ECDH lock for client %s", client.addr)
			<-client.roundECDHLock
			s.logger.Trace("ECDH lock acquired for client %s", client.addr)
		}

		salt := []byte{}
		if s.config.UpdateThroughSalt {
			salt, err = crypto.RandomBytes(8)
			if err != nil {
				s.logger.Error("Failed to generate salt for client %s: %v", client.addr, err)
				continue
			}
			s.logger.Trace("Salt generated for client %s: %x", client.addr, salt)

		}

		packet := packets.NewPlainPacket()
		packet.AddData(rawPacket)

		needsECDH := client.countSent >= uint32(math.Pow(2, 16)) || time.Since(client.lastRoundECDH) >= 4*time.Minute
		s.logger.Trace("Client %s: countSent=%d, lastRoundECDH=%v, needsECDH=%v",
			client.addr, client.countSent, time.Since(client.lastRoundECDH), needsECDH)

		if needsECDH {
			s.logger.Debug("Initiating ECDH rekey for client %s (countSent=%d, lastRoundECDH=%v)",
				client.addr, client.countSent, time.Since(client.lastRoundECDH))

			curve := ecdh.X25519()
			privateKey, err := curve.GenerateKey(rand.Reader)
			if err != nil {
				s.logger.Error("Failed to generate ephemeral key for client %s: %v", client.addr, err)
				return
			}
			s.logger.Trace("Ephemeral key pair generated for client %s", client.addr)

			client.ephemeralPrivateServerKey = privateKey
			err = packet.PackageAssembly(client.sessionSentKey, salt, privateKey.PublicKey().Bytes(), false, true)
			if err != nil {
				s.logger.Error("Failed to package packet with ECDH for client %s: %v", client.addr, err)
				continue
			}
			s.logger.Trace("Packet assembled with ECDH flag for client %s", client.addr)
		} else {
			err = packet.PackageAssembly(client.sessionSentKey, salt, []byte{}, false, false)
			if err != nil {
				s.logger.Error("Failed to package packet for client %s: %v", client.addr, err)
				continue
			}
			s.logger.Trace("Packet assembled without ECDH flag for client %s", client.addr)
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
		s.logger.Trace("Packet written to client %s, size=%d bytes", client.addr, len(packet.GetRawData()))

		if packet.GetEcdhFlag() {
			s.logger.Debug("ECDH flag set for client %s, creating lock", client.addr)
			client.roundECDHLock = make(chan struct{}, 1)
		}

		if s.config.UpdateThroughSalt {
			client.computeNextSessionSentKey(salt)
		}
		client.countSent++
		s.logger.Trace("Client %s: session sent key updated, countSent=%d", client.addr, client.countSent)
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
			s.logger.Trace("Packet received from client %s, size=%d bytes", client.addr, len(packet.GetRawData()))

			err = packet.DecodeAndDecrypt(client.sessionRecvKey)
			if err != nil {
				s.logger.Error("Failed to decrypt packet from client %s: %v", client.addr, err)
				continue
			}
			s.logger.Trace("Packet decrypted successfully for client %s", client.addr)

			client.countRecv++
			salt := packet.GetSalt()
			if len(salt) != 0 {
				client.computeNextSessionRecvKey(salt)
				s.logger.Trace("Client %s: countRecv=%d, session recv key updated", client.addr, client.countRecv)
			}

			if packet.GetEcdhFlag() && client.ephemeralPrivateServerKey != nil {
				s.logger.Debug("Processing ECDH rekey from client %s", client.addr)

				curve := ecdh.X25519()
				clientPublicKey, err := curve.NewPublicKey(packet.GetPublicKey())
				if err != nil {
					s.logger.Error("Failed to parse client public key for %s: %v", client.addr, err)
					return
				}
				s.logger.Trace("Client public key parsed for %s", client.addr)

				secret, err := client.ephemeralPrivateServerKey.ECDH(clientPublicKey)
				if err != nil {
					s.logger.Error("Failed to compute shared secret for client %s: %v", client.addr, err)
					return
				}
				s.logger.Trace("Shared secret computed for client %s", client.addr)

				client.ephemeralPrivateServerKey = nil
				client.lastRoundECDH = time.Now()

				client.countRecv = 0
				client.countSent = 0
				s.logger.Trace("Client %s: counters reset (recv=0, sent=0), lastRoundECDH updated", client.addr)

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
			s.logger.Trace("Client %s: lastActive updated, countRecvBytes=%d", client.addr, client.countRecvBytes)

			ipSrc, err := packet.GetSlicePlainData(12, 16)
			if err != nil {
				s.logger.Error("Failed to get source IP from packet for client %s: %v", client.addr, err)
				continue
			}

			srcIP := fmt.Sprintf("%d.%d.%d.%d", ipSrc[0], ipSrc[1], ipSrc[2], ipSrc[3])
			if srcIP != client.localIP.String() {
				s.logger.Error("Source IP mismatch for client %s: expected %s, got %s", client.addr, client.localIP.String(), srcIP)
				continue
			}
			s.logger.Trace("Source IP validated for client %s: %s", client.addr, srcIP)

			_, err = s.tunnel.Write(packet.GetPlainData())
			if err != nil {
				s.logger.Error("Failed to write packet to tunnel for client %s: %v", client.addr, err)
				continue
			}
			s.logger.Trace("Packet written to tunnel for client %s", client.addr)
		}
	}
}

func (s *Server) cleanupIdleClients() {
	s.logger.Debug("Cleanup idle clients goroutine started")
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			s.logger.Debug("Cleanup goroutine received stop signal, exiting")
			return
		case <-ticker.C:
			s.logger.Trace("Running idle clients cleanup check")

			s.mu.Lock()
			idleCount := 0
			for addr, client := range s.clients {
				idleTime := time.Since(client.lastActive)
				if idleTime > 10*time.Minute {
					s.logger.Info("Client %s (IP: %s) idle for %v, disconnecting", client.addr, addr, idleTime)
					client.conn.Close()
					s.ipPool.ReleaseIP(*client.localIP)
					delete(s.clients, addr)
					idleCount++
				}
			}
			if idleCount > 0 {
				s.logger.Debug("Cleaned up %d idle clients", idleCount)
			} else {
				s.logger.Trace("No idle clients found")
			}
			s.mu.Unlock()
		}
	}
}

func (s *Server) incrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount++
	s.logger.Trace("Client count incremented to %d", s.clientCount)
}

func (s *Server) decrementClientCount() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clientCount--
	s.logger.Trace("Client count decremented to %d", s.clientCount)
}

func (s *Server) GetClientCount() int32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.clientCount
}
