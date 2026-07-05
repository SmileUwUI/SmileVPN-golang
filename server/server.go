package server

import (
	"SmileVPN/internal/crypto"
	"SmileVPN/internal/logger"
	"SmileVPN/internal/packets"
	"SmileVPN/internal/tunnel"
	"SmileVPN/server/config"
	"SmileVPN/server/users"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
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
				if err != context.DeadlineExceeded {
					s.logger.Error("Tunnel read error: %v", err)
				}
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
			packet.AddParameter("salt", salt)

			needsECDH := client.countSent.Load() >= uint32(math.Pow(2, 16)) || time.Since(client.lastRoundECDH) >= 4*time.Minute
			s.logger.Trace("Client %s: countSent=%d, lastRoundECDH=%v, needsECDH=%v",
				client.addr, client.countSent.Load(), time.Since(client.lastRoundECDH), needsECDH)

			if needsECDH {
				s.logger.Debug("Initiating ECDH rekey for client %s (countSent=%d, lastRoundECDH=%v)",
					client.addr, client.countSent.Load(), time.Since(client.lastRoundECDH))

				curve := ecdh.X25519()
				privateKey, err := curve.GenerateKey(rand.Reader)
				if err != nil {
					s.logger.Error("Failed to generate ephemeral key for client %s: %v", client.addr, err)
					return
				}
				s.logger.Trace("Ephemeral key pair generated for client %s", client.addr)

				client.ephemeralPrivateServerKey = privateKey
				packet.AddParameter("publicKey", privateKey.PublicKey().Bytes())
				err = packet.PackageAssembly(client.sessionSentKey.GetBytes(), false, false)
				if err != nil {
					s.logger.Error("Failed to package packet with ECDH for client %s: %v", client.addr, err)
					continue
				}
				s.logger.Trace("Packet assembled with ECDH flag for client %s", client.addr)
			} else {
				err = packet.PackageAssembly(client.sessionSentKey.GetBytes(), false, false)
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
					s.disconnectClient(client.localIP.String())
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
				err = client.computeNextSessionSentKey(salt)
				if err != nil {
					s.logger.Error("Failed to compute next session sent key for client %s: %v", client.addr, err)
					continue
				}
			}
			client.countSent.Add(1)
			s.logger.Trace("Client %s: session sent key updated, countSent=%d", client.addr, client.countSent.Load())
		}
	}
}

func (s *Server) handleClient(client *Client) {
	s.logger.Info("Starting to handle client %s (IP: %s)", client.addr, client.localIP.String())
	defer func() {
		s.logger.Info("Stopping to handle client %s (IP: %s)", client.addr, client.localIP.String())
		s.wg.Done()
		err := client.conn.Close()
		if err != nil {
			s.logger.Error("Failed to close client %s: %v", client.addr, err)
		}
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
					s.disconnectClient(client.localIP.String())
					return
				}

				if errors.Is(err, io.EOF) {
					s.logger.Info("Client %s disconnected (EOF), releasing IP %s", client.addr, client.localIP.String())
					s.disconnectClient(client.localIP.String())
					return
				}
				s.logger.Error("Failed to read packet from client %s: %v", client.addr, err)
				continue
			}
			s.logger.Trace("Packet received from client %s, size=%d bytes", client.addr, len(packet.GetRawData()))

			err = packet.DecodeAndDecrypt(client.sessionRecvKey.GetBytes())
			if err != nil {
				s.logger.Error("Failed to decrypt packet from client %s: %v", client.addr, err)
				continue
			}
			s.logger.Trace("Packet decrypted successfully for client %s", client.addr)
			if packet.GetDisconnectFlag() {
				s.logger.Info("Client %s disconnected, releasing IP %s", client.addr, client.localIP.String())
				s.disconnectClient(client.localIP.String())
				return
			}

			client.countRecv.Add(1)
			salt := packet.GetSalt()
			if len(salt) != 0 {
				err = client.computeNextSessionRecvKey(salt)
				if err != nil {
					s.logger.Error("Failed to compute next session recv key for client %s: %v", client.addr, err)
					return
				}
				s.logger.Trace("Client %s: countRecv=%d, session recv key updated", client.addr, client.countRecv.Load())
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

				client.countRecv.Store(0)
				client.countSent.Store(0)
				s.logger.Trace("Client %s: counters reset (recv=0, sent=0), lastRoundECDH updated", client.addr)

				err = client.computeNextSessionSentKey(secret)
				if err != nil {
					s.logger.Error("Failed to compute next session sent key for %s: %v", client.addr, err)
					return
				}
				err = client.computeNextSessionRecvKey(secret)
				if err != nil {
					s.logger.Error("Failed to compute next session recv key for %s: %v", client.addr, err)
					return
				}
				close(client.roundECDHLock)

				s.logger.Info("ECDH rekey completed for client %s", client.addr)
			}

			client.mu.Lock()
			client.lastActive = time.Now()

			countRecv := len(packet.GetRawData())
			if countRecv < 0 {
				countRecv = 0
			}

			client.countRecvBytes.Add(uint32(countRecv))
			client.mu.Unlock()
			s.logger.Trace("Client %s: lastActive updated, countRecvBytes=%d", client.addr, client.countRecvBytes.Load())

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
