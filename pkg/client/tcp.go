package client

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// TCPConnectionPool manages TCP connections for reuse
type TCPConnectionPool struct {
	connections map[string]*TCPPooledConnection
	mu          sync.RWMutex
	maxIdle     int
	maxLifetime time.Duration
	logger      log.Logger
}

// TCPPooledConnection represents a pooled TCP connection
type TCPPooledConnection struct {
	conn       net.Conn
	serverAddr string
	created    time.Time
	lastUsed   time.Time
	inUse      bool
	mu         sync.RWMutex
}

// NewTCPConnectionPool creates a new TCP connection pool
func NewTCPConnectionPool(maxIdle int, maxLifetime time.Duration, logger log.Logger) *TCPConnectionPool {
	if maxIdle <= 0 {
		maxIdle = 5
	}
	if maxLifetime <= 0 {
		maxLifetime = 10 * time.Minute
	}

	pool := &TCPConnectionPool{
		connections: make(map[string]*TCPPooledConnection),
		maxIdle:     maxIdle,
		maxLifetime: maxLifetime,
		logger:      logger,
	}

	// Start cleanup goroutine
	go pool.cleanupRoutine()

	return pool
}

// GetConnection gets a connection from the pool or creates a new one
func (p *TCPConnectionPool) GetConnection(serverAddr string, timeout time.Duration, tlsConfig *tls.Config) (*TCPPooledConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to find an existing connection
	if conn, exists := p.connections[serverAddr]; exists {
		conn.mu.Lock()
		if !conn.inUse && time.Since(conn.created) < p.maxLifetime {
			// Test if connection is still alive
			if conn.conn != nil {
				conn.conn.SetReadDeadline(time.Now().Add(1 * time.Millisecond))
				buffer := make([]byte, 1)
				_, err := conn.conn.Read(buffer)
				conn.conn.SetReadDeadline(time.Time{})

				// If read didn't timeout, connection might be dead
				if err == nil {
					conn.Close()
					conn.mu.Unlock()
					delete(p.connections, serverAddr)
				} else {
					// Connection is alive
					conn.inUse = true
					conn.lastUsed = time.Now()
					conn.mu.Unlock()
					return conn, nil
				}
			}
		} else {
			conn.mu.Unlock()
			// Connection is expired or in use, remove it
			conn.Close()
			delete(p.connections, serverAddr)
		}
	}

	// Create new connection
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	var conn net.Conn
	var err error

	// Use TLS if configured
	if tlsConfig != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS connection: %w", err)
		}

		// Verify TLS handshake
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, fmt.Errorf("TLS handshake failed: %w", err)
			}
		}
	} else {
		conn, err = dialer.Dial("tcp", serverAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to create TCP connection: %w", err)
		}
	}

	pooledConn := &TCPPooledConnection{
		conn:       conn,
		serverAddr: serverAddr,
		created:    time.Now(),
		lastUsed:   time.Now(),
		inUse:      true,
	}

	p.connections[serverAddr] = pooledConn
	return pooledConn, nil
}

// ReleaseConnection releases a connection back to the pool
func (p *TCPConnectionPool) ReleaseConnection(conn *TCPPooledConnection) {
	if conn == nil {
		return
	}

	conn.mu.Lock()
	conn.inUse = false
	conn.lastUsed = time.Now()
	conn.mu.Unlock()
}

// Close closes a pooled connection
func (c *TCPPooledConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		return err
	}
	return nil
}

// cleanupRoutine periodically cleans up expired connections
func (p *TCPConnectionPool) cleanupRoutine() {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()

		for addr, conn := range p.connections {
			conn.mu.RLock()
			expired := now.Sub(conn.created) > p.maxLifetime
			unused := !conn.inUse && now.Sub(conn.lastUsed) > 5*time.Minute
			conn.mu.RUnlock()

			if expired || unused {
				conn.Close()
				delete(p.connections, addr)
				if p.logger != nil {
					p.logger.Debugf("Cleaned up expired TCP connection: %s", addr)
				}
			}
		}
		p.mu.Unlock()
	}
}

// Close closes all connections in the pool
func (p *TCPConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, conn := range p.connections {
		conn.Close()
		delete(p.connections, addr)
	}

	return nil
}

// TCPClient represents a TCP RADIUS client
type TCPClient struct {
	// Configuration
	serverAddr   string
	sharedSecret []byte
	timeout      time.Duration
	tlsConfig    *tls.Config // For TLS support (RADSEC)

	// Connection management
	conn       net.Conn
	connMu     sync.RWMutex
	connecting bool
	connected  bool

	// Connection pooling
	connPool    *TCPConnectionPool
	keepAlive   bool
	maxIdleTime time.Duration

	// Logger
	logger log.Logger

	// Statistics
	stats *TCPStatistics
}

// TCPStatistics holds TCP client statistics
type TCPStatistics struct {
	mu sync.RWMutex

	// Connection statistics
	ConnectionAttempts uint64
	ConnectionFailures uint64
	ConnectionReuses   uint64
	DisconnectionCount uint64

	// Request statistics
	RequestsSent      uint64
	ResponsesReceived uint64
	Timeouts          uint64
	Errors            uint64

	// Bytes transferred
	BytesSent     uint64
	BytesReceived uint64

	// Timing
	LastRequest  time.Time
	LastResponse time.Time
	AverageRTT   time.Duration
}

// NewTCPClient creates a new TCP RADIUS client
func NewTCPClient(serverAddr string, sharedSecret []byte, timeout time.Duration, logger log.Logger) (*TCPClient, error) {
	return NewTCPClientWithTLS(serverAddr, sharedSecret, timeout, nil, logger)
}

// NewTCPClientWithTLS creates a new TCP RADIUS client with optional TLS support
func NewTCPClientWithTLS(serverAddr string, sharedSecret []byte, timeout time.Duration, tlsConfig *tls.Config, logger log.Logger) (*TCPClient, error) {
	if serverAddr == "" {
		return nil, fmt.Errorf("server address cannot be empty")
	}

	if len(sharedSecret) == 0 {
		return nil, fmt.Errorf("shared secret cannot be empty")
	}

	if timeout <= 0 {
		timeout = 30 * time.Second
	}

	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	return &TCPClient{
		serverAddr:   serverAddr,
		sharedSecret: sharedSecret,
		timeout:      timeout,
		tlsConfig:    tlsConfig,
		keepAlive:    true,
		maxIdleTime:  5 * time.Minute,
		logger:       logger,
		stats:        &TCPStatistics{},
	}, nil
}

// NewTCPClientWithPool creates a new TCP RADIUS client with connection pooling
func NewTCPClientWithPool(serverAddr string, sharedSecret []byte, timeout time.Duration, pool *TCPConnectionPool, logger log.Logger) (*TCPClient, error) {
	return NewTCPClientWithTLSAndPool(serverAddr, sharedSecret, timeout, nil, pool, logger)
}

// NewTCPClientWithTLSAndPool creates a new TCP RADIUS client with TLS and connection pooling
func NewTCPClientWithTLSAndPool(serverAddr string, sharedSecret []byte, timeout time.Duration, tlsConfig *tls.Config, pool *TCPConnectionPool, logger log.Logger) (*TCPClient, error) {
	client, err := NewTCPClientWithTLS(serverAddr, sharedSecret, timeout, tlsConfig, logger)
	if err != nil {
		return nil, err
	}

	client.connPool = pool
	return client, nil
}

// SetKeepAlive sets the keep-alive behavior for the TCP client
func (c *TCPClient) SetKeepAlive(keepAlive bool) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.keepAlive = keepAlive
}

// SetMaxIdleTime sets the maximum idle time for connections
func (c *TCPClient) SetMaxIdleTime(maxIdleTime time.Duration) {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.maxIdleTime = maxIdleTime
}

// Connect establishes a connection to the RADIUS server
func (c *TCPClient) Connect(ctx context.Context) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	// Check if already connected
	if c.connected && c.conn != nil {
		return nil
	}

	// Check if already connecting
	if c.connecting {
		return fmt.Errorf("connection already in progress")
	}

	c.connecting = true
	defer func() {
		c.connecting = false
	}()

	c.stats.mu.Lock()
	c.stats.ConnectionAttempts++
	c.stats.mu.Unlock()

	// Create connection with timeout
	dialer := &net.Dialer{
		Timeout: c.timeout,
	}

	var conn net.Conn
	var err error

	// Use TLS if configured
	if c.tlsConfig != nil {
		conn, err = tls.DialWithDialer(dialer, "tcp", c.serverAddr, c.tlsConfig)
		if err != nil {
			c.stats.mu.Lock()
			c.stats.ConnectionFailures++
			c.stats.mu.Unlock()
			return fmt.Errorf("failed to connect to %s with TLS: %w", c.serverAddr, err)
		}

		// Verify TLS handshake
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				c.stats.mu.Lock()
				c.stats.ConnectionFailures++
				c.stats.mu.Unlock()
				return fmt.Errorf("TLS handshake failed: %w", err)
			}
		}
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", c.serverAddr)
		if err != nil {
			c.stats.mu.Lock()
			c.stats.ConnectionFailures++
			c.stats.mu.Unlock()
			return fmt.Errorf("failed to connect to %s: %w", c.serverAddr, err)
		}
	}

	c.conn = conn
	c.connected = true
	c.logger.Infof("Connected to RADIUS server at %s", c.serverAddr)

	return nil
}

// Disconnect closes the connection to the RADIUS server
func (c *TCPClient) Disconnect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	if c.conn != nil {
		err := c.conn.Close()
		c.conn = nil
		c.connected = false

		c.stats.mu.Lock()
		c.stats.DisconnectionCount++
		c.stats.mu.Unlock()

		c.logger.Info("Disconnected from RADIUS server")
		return err
	}

	return nil
}

// SendRequest sends a RADIUS request and waits for a response
func (c *TCPClient) SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
	if req == nil {
		return nil, fmt.Errorf("request packet cannot be nil")
	}

	startTime := time.Now()

	// Use connection pooling if available
	if c.connPool != nil {
		return c.sendRequestWithPool(ctx, req, startTime)
	}

	// Ensure connection is established
	if err := c.Connect(ctx); err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}

	// Send request
	response, err := c.sendRequestWithConnection(ctx, req)
	if err != nil {
		// If connection error, try to reconnect once
		if isConnectionError(err) {
			c.logger.Warnf("Connection error, attempting to reconnect: %v", err)
			c.Disconnect()

			if reconnectErr := c.Connect(ctx); reconnectErr != nil {
				return nil, fmt.Errorf("failed to reconnect: %w", reconnectErr)
			}

			// Retry request
			response, err = c.sendRequestWithConnection(ctx, req)
		}

		if err != nil {
			c.stats.mu.Lock()
			c.stats.Errors++
			c.stats.mu.Unlock()
			return nil, err
		}
	}

	// Update statistics
	rtt := time.Since(startTime)
	c.stats.mu.Lock()
	c.stats.RequestsSent++
	c.stats.ResponsesReceived++
	c.stats.LastRequest = startTime
	c.stats.LastResponse = time.Now()
	c.stats.AverageRTT = (c.stats.AverageRTT + rtt) / 2
	c.stats.mu.Unlock()

	return response, nil
}

// sendRequestWithPool sends a request using connection pooling
func (c *TCPClient) sendRequestWithPool(ctx context.Context, req *packet.Packet, startTime time.Time) (*packet.Packet, error) {
	// Get connection from pool
	pooledConn, err := c.connPool.GetConnection(c.serverAddr, c.timeout, c.tlsConfig)
	if err != nil {
		c.stats.mu.Lock()
		c.stats.Errors++
		c.stats.mu.Unlock()
		return nil, fmt.Errorf("failed to get connection from pool: %w", err)
	}
	defer c.connPool.ReleaseConnection(pooledConn)

	// Send request using pooled connection
	response, err := c.sendRequestWithPooledConnection(ctx, req, pooledConn)
	if err != nil {
		// If connection error, try to reconnect once
		if isConnectionError(err) {
			c.logger.Warnf("Connection error, attempting to reconnect: %v", err)

			// Close the bad connection and remove it from pool
			pooledConn.Close()

			// Get a new connection from pool
			newPooledConn, reconnectErr := c.connPool.GetConnection(c.serverAddr, c.timeout, c.tlsConfig)
			if reconnectErr != nil {
				return nil, fmt.Errorf("failed to reconnect: %w", reconnectErr)
			}
			defer c.connPool.ReleaseConnection(newPooledConn)

			// Retry request
			response, err = c.sendRequestWithPooledConnection(ctx, req, newPooledConn)
		}

		if err != nil {
			c.stats.mu.Lock()
			c.stats.Errors++
			c.stats.mu.Unlock()
			return nil, err
		}
	}

	// Update statistics
	rtt := time.Since(startTime)
	c.stats.mu.Lock()
	c.stats.RequestsSent++
	c.stats.ResponsesReceived++
	c.stats.LastRequest = startTime
	c.stats.LastResponse = time.Now()
	c.stats.AverageRTT = (c.stats.AverageRTT + rtt) / 2
	c.stats.ConnectionReuses++
	c.stats.mu.Unlock()

	return response, nil
}

// sendRequestWithPooledConnection sends a request using a pooled connection
func (c *TCPClient) sendRequestWithPooledConnection(_ context.Context, req *packet.Packet, pooledConn *TCPPooledConnection) (*packet.Packet, error) {
	pooledConn.mu.RLock()
	conn := pooledConn.conn
	pooledConn.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("pooled connection is nil")
	}

	// Encode request packet
	requestData, err := req.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	// Create length-prefixed packet
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(requestData)+2))

	// Send with timeout
	if err := conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Send length prefix
	if _, err := conn.Write(lengthPrefix); err != nil {
		return nil, fmt.Errorf("failed to send length prefix: %w", err)
	}

	// Send packet data
	if _, err := conn.Write(requestData); err != nil {
		return nil, fmt.Errorf("failed to send packet data: %w", err)
	}

	// Update statistics
	c.stats.mu.Lock()
	c.stats.BytesSent += uint64(len(requestData) + 2)
	c.stats.mu.Unlock()

	// Read response with timeout
	if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read response length
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("connection closed by server")
		}
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	// Parse response length
	responseLength := binary.BigEndian.Uint16(lengthBuf)
	if responseLength < 2 || responseLength > 4096 {
		return nil, fmt.Errorf("invalid response length: %d", responseLength)
	}

	// Read response data
	responseData := make([]byte, responseLength-2)
	if _, err := io.ReadFull(conn, responseData); err != nil {
		return nil, fmt.Errorf("failed to read response data: %w", err)
	}

	// Update statistics
	c.stats.mu.Lock()
	c.stats.BytesReceived += uint64(len(responseData) + 2)
	c.stats.mu.Unlock()

	// Decode response packet
	response, err := packet.Decode(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil
}

// sendRequestWithConnection sends a request using the existing connection
func (c *TCPClient) sendRequestWithConnection(_ context.Context, req *packet.Packet) (*packet.Packet, error) {
	c.connMu.RLock()
	conn := c.conn
	c.connMu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected to server")
	}

	// Encode request packet
	requestData, err := req.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	// Create length-prefixed packet
	lengthPrefix := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthPrefix, uint16(len(requestData)+2))

	// Send with timeout
	if err := conn.SetWriteDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set write deadline: %w", err)
	}

	// Send length prefix
	if _, err := conn.Write(lengthPrefix); err != nil {
		return nil, fmt.Errorf("failed to send length prefix: %w", err)
	}

	// Send packet data
	if _, err := conn.Write(requestData); err != nil {
		return nil, fmt.Errorf("failed to send packet data: %w", err)
	}

	// Update statistics
	c.stats.mu.Lock()
	c.stats.BytesSent += uint64(len(requestData) + 2)
	c.stats.mu.Unlock()

	// Read response with timeout
	if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Read response length
	lengthBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lengthBuf); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("connection closed by server")
		}
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}

	// Parse response length
	responseLength := binary.BigEndian.Uint16(lengthBuf)
	if responseLength < 2 || responseLength > 4096 {
		return nil, fmt.Errorf("invalid response length: %d", responseLength)
	}

	// Read response data
	responseData := make([]byte, responseLength-2)
	if _, err := io.ReadFull(conn, responseData); err != nil {
		return nil, fmt.Errorf("failed to read response data: %w", err)
	}

	// Update statistics
	c.stats.mu.Lock()
	c.stats.BytesReceived += uint64(len(responseData) + 2)
	c.stats.mu.Unlock()

	// Decode response packet
	response, err := packet.Decode(responseData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return response, nil
}

// GetStatistics returns client statistics
func (c *TCPClient) GetStatistics() *Statistics {
	c.stats.mu.RLock()
	defer c.stats.mu.RUnlock()

	// Return a copy to prevent external modification
	return &Statistics{
		RequestsSent:        int64(c.stats.RequestsSent),
		ResponsesReceived:   int64(c.stats.ResponsesReceived),
		Timeouts:            int64(c.stats.Timeouts),
		Errors:              int64(c.stats.Errors),
		ConnectionsTotal:    int64(c.stats.ConnectionAttempts),
		ConnectionsFailures: int64(c.stats.ConnectionFailures),
		BytesSent:           int64(c.stats.BytesSent),
		BytesReceived:       int64(c.stats.BytesReceived),
		AverageRTT:          c.stats.AverageRTT,
	}
}

// IsConnected returns true if the client is connected to the server
func (c *TCPClient) IsConnected() bool {
	c.connMu.RLock()
	defer c.connMu.RUnlock()
	return c.connected && c.conn != nil
}

// GetServerAddress returns the server address
func (c *TCPClient) GetServerAddress() string {
	return c.serverAddr
}

// SetTimeout sets the request timeout
func (c *TCPClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// GetTimeout returns the current timeout
func (c *TCPClient) GetTimeout() time.Duration {
	return c.timeout
}

// SetTLSConfig sets the TLS configuration
func (c *TCPClient) SetTLSConfig(tlsConfig *tls.Config) {
	c.tlsConfig = tlsConfig
}

// GetTLSConfig returns the current TLS configuration
func (c *TCPClient) GetTLSConfig() *tls.Config {
	return c.tlsConfig
}

// IsTLSEnabled returns true if TLS is configured
func (c *TCPClient) IsTLSEnabled() bool {
	return c.tlsConfig != nil
}

// GetTLSConnectionState returns the TLS connection state if available
func (c *TCPClient) GetTLSConnectionState() (tls.ConnectionState, error) {
	c.connMu.RLock()
	defer c.connMu.RUnlock()

	if c.conn == nil {
		return tls.ConnectionState{}, fmt.Errorf("not connected")
	}

	if tlsConn, ok := c.conn.(*tls.Conn); ok {
		return tlsConn.ConnectionState(), nil
	}

	return tls.ConnectionState{}, fmt.Errorf("connection is not TLS")
}

// isConnectionError checks if the error is a connection-related error
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors
	if netErr, ok := err.(net.Error); ok {
		return !netErr.Timeout()
	}

	// Check for common connection errors
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "connection closed") ||
		strings.Contains(errStr, "broken pipe") ||
		strings.Contains(errStr, "no route to host")
}
