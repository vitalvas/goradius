package server

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// TCPListener handles TCP connections for a specific binding
type TCPListener struct {
	// Configuration
	binding Binding
	config  *Config

	// Network listener - protected by listenerMu
	listener   net.Listener
	listenerMu sync.RWMutex

	// Handler
	handler Handler

	// Connection management
	connections map[string]*TCPConnection
	connMu      sync.RWMutex

	// Worker pool
	workers chan struct{}

	// Logger
	logger log.Logger

	// Context for shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Statistics
	stats *ListenerStatistics
}

// TCPConnection represents a single TCP connection
type TCPConnection struct {
	// Network connection
	conn    net.Conn
	tlsConn *tls.Conn // Set if this is a TLS connection

	// Client information
	clientAddr   net.Addr
	clientConfig *ClientConfig
	clientCerts  [][]byte // DER-encoded client certificates (for TLS)

	// Connection state
	connected time.Time
	lastSeen  time.Time
	mu        sync.RWMutex

	// Processing context
	ctx    context.Context
	cancel context.CancelFunc

	// Parent listener
	listener *TCPListener

	// Statistics
	bytesReceived uint64
	bytesSent     uint64
	requests      uint64
	responses     uint64
	errors        uint64
}

// NewTCPListener creates a new TCP listener
func NewTCPListener(parentCtx context.Context, binding Binding, config *Config, handler Handler, logger log.Logger) (*TCPListener, error) {
	ctx, cancel := context.WithCancel(parentCtx)

	return &TCPListener{
		binding:     binding,
		config:      config,
		handler:     handler,
		connections: make(map[string]*TCPConnection),
		workers:     make(chan struct{}, config.Workers),
		logger:      logger,
		ctx:         ctx,
		cancel:      cancel,
		stats:       NewListenerStatistics(),
	}, nil
}

// Listen starts the TCP listener and begins accepting connections
func (l *TCPListener) Listen() error {
	// Determine network type based on IP version
	var network string
	switch l.binding.IPVersion {
	case 4:
		network = "tcp4"
	case 6:
		network = "tcp6"
	default:
		network = "tcp" // Dual-stack
	}

	// Create listen address
	listenAddr := fmt.Sprintf("%s:%d", l.binding.Address, l.binding.Port)
	if l.binding.IPVersion == 6 && l.binding.Address != "::" {
		listenAddr = fmt.Sprintf("[%s]:%d", l.binding.Address, l.binding.Port)
	}

	// Create TCP listener (with TLS if configured)
	var listener net.Listener
	var err error

	if l.binding.TLSConfig != nil {
		// Create TLS listener
		listener, err = tls.Listen(network, listenAddr, l.binding.TLSConfig)
		if err != nil {
			return fmt.Errorf("failed to listen on %s with TLS: %w", listenAddr, err)
		}
		l.logger.Infof("TCP listener with TLS starting on %s", listener.Addr())
	} else {
		// Create regular TCP listener
		listener, err = net.Listen(network, listenAddr)
		if err != nil {
			return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
		}
		l.logger.Infof("TCP listener starting on %s", listener.Addr())
	}

	// Set listener with proper synchronization
	l.listenerMu.Lock()
	l.listener = listener
	// Update binding port if it was 0 (random port)
	if l.binding.Port == 0 {
		if tcpAddr, ok := listener.Addr().(*net.TCPAddr); ok {
			l.binding.Port = tcpAddr.Port
		}
	}
	l.listenerMu.Unlock()

	// Initialize worker pool
	for i := 0; i < l.config.Workers; i++ {
		l.workers <- struct{}{}
	}

	// Start connection cleanup goroutine
	l.wg.Add(1)
	go l.connectionCleanup()

	defer func() {
		listener.Close()
		l.logger.Infof("TCP listener stopped on %s", listener.Addr())
	}()

	// Accept connections
	for {
		select {
		case <-l.ctx.Done():
			return nil
		default:
			// Set accept timeout
			if tcpListener, ok := listener.(*net.TCPListener); ok {
				tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
			}

			conn, err := listener.Accept()
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if l.ctx.Err() != nil {
					return nil
				}
				l.logger.Errorf("Error accepting TCP connection: %v", err)
				continue
			}

			// Handle TLS handshake if applicable
			if l.binding.TLSConfig != nil {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					if err := tlsConn.Handshake(); err != nil {
						l.logger.Warnf("TLS handshake failed for %s: %v", conn.RemoteAddr(), err)
						conn.Close()
						continue
					}
				}
			}

			// Handle connection
			l.wg.Add(1)
			go l.handleConnection(conn)
		}
	}
}

// Stop stops the TCP listener
func (l *TCPListener) Stop() {
	l.listenerMu.RLock()
	if l.listener != nil {
		l.logger.Infof("Stopping TCP listener on %s", l.listener.Addr())
	}
	l.listenerMu.RUnlock()

	l.cancel()

	// Close all connections
	l.connMu.Lock()
	for _, conn := range l.connections {
		conn.close()
	}
	l.connMu.Unlock()

	// Close listener
	l.listenerMu.Lock()
	if l.listener != nil {
		l.listener.Close()
	}
	l.listenerMu.Unlock()

	l.wg.Wait()
}

// handleConnection handles a new TCP connection
func (l *TCPListener) handleConnection(conn net.Conn) {
	defer l.wg.Done()

	clientAddr := conn.RemoteAddr()
	connKey := clientAddr.String()

	l.logger.Debugf("New TCP connection from %s", clientAddr)

	// Validate client
	clientConfig, err := l.validateClient(clientAddr)
	if err != nil {
		l.logger.Warnf("Client validation failed for %s: %v", clientAddr, err)
		conn.Close()
		return
	}

	// Create connection context
	connCtx, connCancel := context.WithCancel(l.ctx)

	// Extract TLS information if applicable
	var tlsConn *tls.Conn
	var clientCerts [][]byte
	if l.binding.TLSConfig != nil {
		if tc, ok := conn.(*tls.Conn); ok {
			tlsConn = tc
			// Extract client certificates
			connState := tc.ConnectionState()
			for _, cert := range connState.PeerCertificates {
				clientCerts = append(clientCerts, cert.Raw)
			}
		}
	}

	// Create TCP connection object
	tcpConn := &TCPConnection{
		conn:         conn,
		tlsConn:      tlsConn,
		clientAddr:   clientAddr,
		clientConfig: clientConfig,
		clientCerts:  clientCerts,
		connected:    time.Now(),
		lastSeen:     time.Now(),
		ctx:          connCtx,
		cancel:       connCancel,
		listener:     l,
	}

	// Register connection
	l.connMu.Lock()
	l.connections[connKey] = tcpConn
	l.connMu.Unlock()

	// Update statistics
	l.stats.mu.Lock()
	l.stats.Connections++
	l.stats.mu.Unlock()

	// Handle connection
	tcpConn.handle()

	// Cleanup
	l.connMu.Lock()
	delete(l.connections, connKey)
	l.connMu.Unlock()

	l.logger.Debugf("TCP connection from %s closed", clientAddr)
}

// handle processes requests from the TCP connection
func (c *TCPConnection) handle() {
	defer c.conn.Close()

	// Set connection timeouts
	if c.listener.config.ReadTimeout > 0 {
		c.conn.SetReadDeadline(time.Now().Add(c.listener.config.ReadTimeout))
	}

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
			// Read length-prefixed packet
			packetData, err := c.readPacket()
			if err != nil {
				if err == io.EOF {
					return // Client closed connection
				}
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				c.listener.logger.Errorf("Error reading packet from %s: %v", c.clientAddr, err)
				c.errors++
				return
			}

			// Update activity
			c.mu.Lock()
			c.lastSeen = time.Now()
			c.bytesReceived += uint64(len(packetData))
			c.requests++
			c.mu.Unlock()

			// Get worker from pool
			select {
			case <-c.listener.workers:
				// Process request in goroutine
				c.listener.wg.Add(1)
				go func(data []byte, received time.Time) {
					defer c.listener.wg.Done()
					defer func() {
						// Return worker to pool
						c.listener.workers <- struct{}{}
					}()

					c.processRequest(data, received)
				}(packetData, time.Now())

			default:
				// No workers available, drop request
				c.listener.logger.Warnf("No workers available, dropping request from %s", c.clientAddr)
				c.mu.Lock()
				c.errors++
				c.mu.Unlock()
			}
		}
	}
}

// readPacket reads a length-prefixed RADIUS packet from the TCP connection
func (c *TCPConnection) readPacket() ([]byte, error) {
	// Read packet length (2 bytes, big-endian)
	lengthBuf := make([]byte, 2)
	_, err := io.ReadFull(c.conn, lengthBuf)
	if err != nil {
		return nil, err
	}

	// Parse length
	length := binary.BigEndian.Uint16(lengthBuf)
	if length < 2 || length > uint16(c.listener.config.MaxRequestSize) {
		return nil, fmt.Errorf("invalid packet length: %d", length)
	}

	// Read packet data
	packetData := make([]byte, length-2)
	_, err = io.ReadFull(c.conn, packetData)
	if err != nil {
		return nil, err
	}

	return packetData, nil
}

// processRequest processes a RADIUS request from the TCP connection
func (c *TCPConnection) processRequest(data []byte, receivedAt time.Time) {
	defer func() {
		if r := recover(); r != nil {
			c.listener.logger.Errorf("Panic processing TCP request from %s: %v", c.clientAddr, r)
		}
	}()

	// Parse RADIUS packet
	radiusPacket, err := packet.Decode(data)
	if err != nil {
		c.listener.logger.Warnf("Failed to parse RADIUS packet from %s: %v", c.clientAddr, err)
		c.mu.Lock()
		c.errors++
		c.mu.Unlock()
		return
	}

	// Create request context with timeout
	ctx, cancel := context.WithTimeout(c.ctx, c.listener.config.ReadTimeout)
	defer cancel()

	// Get server address with proper synchronization
	c.listener.listenerMu.RLock()
	serverAddr := c.listener.listener.Addr()
	c.listener.listenerMu.RUnlock()

	// Create request
	request := &Request{
		ClientAddr: c.clientAddr,
		ServerAddr: serverAddr,
		Packet:     radiusPacket,
		Client:     c.clientConfig,
		ReceivedAt: receivedAt,
	}

	// Process request through handler
	response, err := c.listener.handler.HandleRequest(ctx, request)
	if err != nil {
		c.listener.logger.Errorf("Error handling TCP request from %s: %v", c.clientAddr, err)
		c.mu.Lock()
		c.errors++
		c.mu.Unlock()
		return
	}

	// Send response if required
	if response != nil && response.Send && response.Packet != nil {
		err = c.sendResponse(response.Packet)
		if err != nil {
			c.listener.logger.Errorf("Error sending TCP response to %s: %v", c.clientAddr, err)
			c.mu.Lock()
			c.errors++
			c.mu.Unlock()
			return
		}
	}

	// Update statistics
	c.mu.Lock()
	c.responses++
	c.mu.Unlock()

	c.listener.logger.Debugf("Processed TCP request from %s", c.clientAddr)
}

// sendResponse sends a length-prefixed RADIUS response packet
func (c *TCPConnection) sendResponse(responsePacket *packet.Packet) error {
	// Encode response packet
	data, err := responsePacket.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode response packet: %w", err)
	}

	// Create length-prefixed packet
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(data)+2))

	// Set write timeout
	if c.listener.config.WriteTimeout > 0 {
		c.conn.SetWriteDeadline(time.Now().Add(c.listener.config.WriteTimeout))
	}

	// Send length prefix
	_, err = c.conn.Write(lengthPrefix)
	if err != nil {
		return fmt.Errorf("failed to send length prefix: %w", err)
	}

	// Send packet data
	_, err = c.conn.Write(data)
	if err != nil {
		return fmt.Errorf("failed to send packet data: %w", err)
	}

	// Update statistics
	c.mu.Lock()
	c.bytesSent += uint64(len(data) + 2)
	c.mu.Unlock()

	return nil
}

// close closes the TCP connection
func (c *TCPConnection) close() {
	c.cancel()
	c.conn.Close()
}

// validateClient validates that the client is allowed to connect
func (l *TCPListener) validateClient(clientAddr net.Addr) (*ClientConfig, error) {
	// Extract IP address
	var clientIP net.IP
	switch addr := clientAddr.(type) {
	case *net.TCPAddr:
		clientIP = addr.IP
	case *net.IPAddr:
		clientIP = addr.IP
	default:
		return nil, fmt.Errorf("unsupported address type: %T", clientAddr)
	}

	// Check against configured clients
	for _, client := range l.binding.Clients {
		for _, network := range client.Networks {
			if isIPInNetwork(clientIP, network) {
				return &client, nil
			}
		}
	}

	return nil, fmt.Errorf("client %s not authorized", clientIP)
}

// connectionCleanup periodically cleans up idle connections
func (l *TCPListener) connectionCleanup() {
	defer l.wg.Done()

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	maxIdle := 5 * time.Minute // Maximum idle time

	for {
		select {
		case <-l.ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			var toClose []string

			l.connMu.RLock()
			for connKey, conn := range l.connections {
				conn.mu.RLock()
				if now.Sub(conn.lastSeen) > maxIdle {
					toClose = append(toClose, connKey)
				}
				conn.mu.RUnlock()
			}
			l.connMu.RUnlock()

			// Close idle connections
			for _, connKey := range toClose {
				l.connMu.Lock()
				if conn, exists := l.connections[connKey]; exists {
					l.logger.Debugf("Closing idle TCP connection from %s", conn.clientAddr)
					conn.close()
					delete(l.connections, connKey)
				}
				l.connMu.Unlock()
			}
		}
	}
}

// GetListenerAddress returns the listener's local address
func (l *TCPListener) GetListenerAddress() net.Addr {
	l.listenerMu.RLock()
	defer l.listenerMu.RUnlock()

	if l.listener != nil {
		return l.listener.Addr()
	}
	return nil
}

// GetPort returns the actual port the listener is bound to
func (l *TCPListener) GetPort() int {
	l.listenerMu.RLock()
	defer l.listenerMu.RUnlock()

	if l.listener != nil {
		if tcpAddr, ok := l.listener.Addr().(*net.TCPAddr); ok {
			return tcpAddr.Port
		}
	}
	return l.binding.Port
}

// GetStatistics returns listener statistics
func (l *TCPListener) GetStatistics() *ListenerStatistics {
	return l.stats
}

// GetConnectionCount returns the number of active connections
func (l *TCPListener) GetConnectionCount() int {
	l.connMu.RLock()
	defer l.connMu.RUnlock()
	return len(l.connections)
}

// GetConnections returns information about active connections
func (l *TCPListener) GetConnections() map[string]*TCPConnectionInfo {
	l.connMu.RLock()
	defer l.connMu.RUnlock()

	result := make(map[string]*TCPConnectionInfo)
	for key, conn := range l.connections {
		conn.mu.RLock()
		result[key] = &TCPConnectionInfo{
			ClientAddr:    conn.clientAddr,
			Connected:     conn.connected,
			LastSeen:      conn.lastSeen,
			BytesReceived: conn.bytesReceived,
			BytesSent:     conn.bytesSent,
			Requests:      conn.requests,
			Responses:     conn.responses,
			Errors:        conn.errors,
		}
		conn.mu.RUnlock()
	}
	return result
}

// TCPConnectionInfo provides information about a TCP connection
type TCPConnectionInfo struct {
	ClientAddr    net.Addr
	Connected     time.Time
	LastSeen      time.Time
	BytesReceived uint64
	BytesSent     uint64
	Requests      uint64
	Responses     uint64
	Errors        uint64
}
