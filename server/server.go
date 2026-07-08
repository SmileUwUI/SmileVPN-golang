package server

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/logger"
	"SmileVPN/internal/tunnel"
	"SmileVPN/server/config"
	"SmileVPN/server/users"
	"crypto/sha256"
	"fmt"
	"net"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	tls "github.com/refraction-networking/utls"
)

type Server struct {
	config      *config.Config
	users       *users.Users
	ipPool      *IPPool
	listener    *net.TCPListener
	wg          sync.WaitGroup
	clientCount atomic.Int32
	clients     sync.Map
	logger      *logger.Logger
	tunnel      *tunnel.LinuxTunnel

	stopCh chan struct{}
	mu     sync.RWMutex
}

func NewServer(cfg *config.Config, usersDB *users.Users, logger *logger.Logger) (server *Server, err error) {
	logger.Trace("Creating new server instance")

	ippool, err := NewIPPool(cfg.NetMask)
	if err != nil {
		logger.Error("Failed to create IP pool: %v", err)
		return nil, fmt.Errorf("error creating ip pool: %v", err)
	}
	logger.Debug("IP pool created with subnet %s", cfg.NetMask)

	return &Server{
		config: cfg,
		users:  usersDB,
		ipPool: ippool,
		stopCh: make(chan struct{}),
		logger: logger,
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

	s.listener, _ = listener.(*net.TCPListener)
	s.logger.Debug("TCP listener created on %s", addr)

	ip, mask, err := net.ParseCIDR(s.config.NetMask)
	if err != nil {
		s.logger.Error("Failed to parse CIDR: %v", err)
		return fmt.Errorf("failed to parse CIDR: %w", err)
	}

	tun, err := tunnel.NewLinuxTunnel(
		"tun0",
		1500,
		ip,
		mask.Mask,
	)

	if err != nil {
		s.logger.Error("Error create tunnel: %v", err)
		return err
	}

	s.tunnel = tun.(*tunnel.LinuxTunnel)
	s.logger.Debug("Tunnel interface tun0 created with MTU=1500, IP=%s", s.config.NetMask)

	err = s.tunnel.Up([]string{}, false, true, true)
	if err != nil {
		s.logger.Error("Failed to bring tunnel up: %v", err)
		return err
	}
	s.logger.Info("Tunnel interface is up")

	s.logger.Info("Starting the main VPN operation cycle")
	s.logger.Debug("Launching goroutines: acceptConnections, tunnelReader, cleanupIdleClients")

	s.wg.Add(3)
	go s.acceptConnections()
	go s.tunnelReader()
	go s.cleanupIdleClients()

	return nil
}

func (s *Server) Stop() {
	s.logger.Debug("Stopping the server")
	close(s.stopCh)
	s.logger.Debug("Closing the tunnel")
	err := s.tunnel.Close(true, false, true)
	if err != nil {
		s.logger.Error("Error closing tunnel: %v", err)
	}
	s.logger.Debug("Waiting for the goroutines to finish")
	s.wg.Wait()
}

func (s *Server) acceptConnections() {
	defer s.wg.Done()
	s.logger.Debug("Accept connections goroutine started")

	for {
		select {
		case <-s.stopCh:
			s.logger.Debug("Accept connections received stop signal, exiting")
			return
		default:
			err := s.listener.SetDeadline(time.Now().Add(5 * time.Second))
			if err != nil {
				s.logger.Error("Failed to set deadline on accept connection: %v", err)
			}
			conn, err := s.listener.Accept()
			if err != nil {
				if errOp, ok := err.(*net.OpError); ok && errOp.Timeout() {
					err = s.listener.SetDeadline(time.Now().Add(5 * time.Second))
					if err != nil {
						s.logger.Error("Failed to set deadline on accept connection: %v", err)
					}
					continue
				}

				select {
				case <-s.stopCh:
					s.logger.Debug("Accept connections received stop signal, exiting")
					return
				default:
					s.logger.Error("Accept error: %v", err)
					continue
				}
			}

			clientCount := int(s.clientCount.Load())
			s.mu.RLock()
			maxClients := s.config.MaxClients
			s.mu.RUnlock()

			if clientCount >= maxClients {
				s.logger.Error("Maximum clients reached (%d), rejecting connection from %s", maxClients, conn.RemoteAddr().String())
				err = conn.Close()
				if err != nil {
					s.logger.Error("Failed to close connection: %v", err)
				}
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
	defer s.wg.Done()
	connTCP := conn.(*net.TCPConn)
	clientAddr := connTCP.RemoteAddr().String()
	s.logger.Trace("Handling new connection from %s", clientAddr)

	now := time.Now()
	cert, err := tls.LoadX509KeyPair(s.config.PathTLSCert, s.config.PathTLSKey)
	if err != nil {
		s.logger.Error("error load: %v", err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   s.config.Host,
	}

	tlsConn := tls.Server(conn, tlsConfig)

	err = tlsConn.Handshake()
	if err != nil {
		s.logger.Error("error handshake: %v", err)
		return
	}

	connTCP = GetRawConn(tlsConn).(*net.TCPConn)

	client := &Client{
		addr:           clientAddr,
		conn:           connTCP,
		sessionRecvKey: crypto.NewKey(sha256.New()),
		sessionSentKey: crypto.NewKey(sha256.New()),
		createdAt:      now,
		lastActive:     now,
		lastRoundECDH:  now,
		logger:         s.logger,
	}
	s.logger.Info("The handshake process with client %s has begun", clientAddr)
	s.logger.Debug("Starting handshake stage 1 for client %s", clientAddr)

	err = client.handshakeStage1(s.config.InitPassword, s.users)
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

	s.clients.Store(clientIP.String(), client)
	s.logger.Debug("Client %s added to clients map with IP %s", clientAddr, clientIP.String())

	err = conn.SetDeadline(time.Time{})
	if err != nil {
		s.logger.Error("Error setting the deadline for client %s: %v", clientAddr, err)
		return
	}
	s.logger.Trace("Deadline cleared for client %s", clientAddr)

	s.wg.Add(1)
	go s.handleClient(client)
}

func (s *Server) tunnelReader() {
	defer s.wg.Done()
	s.logger.Info("Tunnel reader started")
	s.logger.Debug("Tunnel reader goroutine: entering main loop")

	for {
		select {
		case <-s.stopCh:
			s.logger.Debug("Tunnel reader stopped")
			return
		default:
			rawPacket := make([]byte, 65535)
			n, err := s.tunnel.Read(rawPacket)
			if err != nil {
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

			clientAny, ok := s.clients.Load(ipStr)
			if !ok {
				s.logger.Debug("No client found for destination IP: %s", ipStr)
				continue
			}
			client := clientAny.(*Client)

			err, disconnect := client.handleTunnelPacket(rawPacket)
			if err != nil {
				s.logger.Error("Error handling packet: %v", err)
			}

			if disconnect {
				s.disconnectClient(client.localIP.String())
			}
		}
	}
}

func (s *Server) handleClient(client *Client) {
	s.logger.Info("Starting to handle client %s (IP: %s)", client.addr, client.localIP.String())
	defer func() {
		s.logger.Info("Stopping to handle client %s (IP: %s)", client.addr, client.localIP.String())
		s.wg.Done()
		s.disconnectClient(client.localIP.String())
	}()

	for {
		select {
		case <-s.stopCh:
			s.logger.Info("Stop signal received, stopping handler for client %s", client.addr)
			return
		default:
			packet, err, disconnect := client.handlePacket()
			if err != nil {
				s.logger.Error("Error handling packet: %v", err)
				continue
			}

			if disconnect {
				s.disconnectClient(client.localIP.String())
				return
			}

			_, err = s.tunnel.Write(packet)
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
	ticker := time.NewTicker(5 * time.Second)
	defer func() {
		s.wg.Done()
		ticker.Stop()
	}()

	for {
		select {
		case <-s.stopCh:
			s.logger.Debug("Cleanup goroutine received stop signal, exiting")
			return
		case <-ticker.C:
			s.logger.Trace("Running idle clients cleanup check")

			idleCount := 0
			s.clients.Range(func(keyAny, valueAny any) bool {
				key := keyAny.(string)
				value := valueAny.(*Client)

				idleTime := time.Since(value.lastActive)
				if idleTime > 1*time.Minute {
					s.logger.Info("Client %s (IP: %s) idle for %v, disconnecting", value.addr, key, idleTime)
					s.disconnectClient(key)
					idleCount++
				}
				return true
			})

			if idleCount > 0 {
				s.logger.Debug("Cleaned up %d idle clients", idleCount)
			} else {
				s.logger.Trace("No idle clients found")
			}
		}
	}
}

func (s *Server) disconnectClient(ip string) {
	clientAny, ok := s.clients.Load(ip)
	if !ok {
		s.logger.Error("The client with IP address %s was not found", ip)
		return
	}

	client := clientAny.(*Client)
	err := client.Close()
	if err != nil {
		client.logger.Error("Failed to close client %s: %v", client.addr, err)
	}
	s.ipPool.ReleaseIP(*client.localIP)
	s.clients.Delete(ip)

	outgoing := exec.Command("conntrack", "-D", "-s", ip)
	if err := outgoing.Run(); err != nil {
		if !strings.Contains(err.Error(), "no such") {
			s.logger.Error("Error deleting outgoing connections: %v", err)
		}
	}

	input := exec.Command("conntrack", "-D", "-d", ip)
	if err := input.Run(); err != nil {
		if !strings.Contains(err.Error(), "no such") {
			s.logger.Error("Error deleting input connections: %v", err)
		}
	}
	s.decrementClientCount()
}

func (s *Server) incrementClientCount() {
	s.clientCount.Add(1)
	s.logger.Trace("Client count incremented to %d", s.clientCount.Load())
}

func (s *Server) decrementClientCount() {
	s.clientCount.Add(-1)
	s.logger.Trace("Client count decremented to %d", s.clientCount.Load())
}

func GetRawConn(tlsConn net.Conn) net.Conn {
	v := reflect.ValueOf(tlsConn).Elem()

	connField := v.FieldByName("conn")
	if !connField.IsValid() {
		panic("field conn not found")
	}

	fieldPtr := unsafe.Pointer(connField.UnsafeAddr())

	connPtr := (*net.Conn)(fieldPtr)

	return *connPtr
}
