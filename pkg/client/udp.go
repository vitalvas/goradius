package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// UDPConnectionPool manages UDP connections for reuse
type UDPConnectionPool struct {
	connections map[string]*UDPPooledConnection
	mu          sync.RWMutex
	maxIdle     int
	maxLifetime time.Duration
	logger      log.Logger
}

// UDPPooledConnection represents a pooled UDP connection
type UDPPooledConnection struct {
	conn      net.PacketConn
	localAddr string
	created   time.Time
	lastUsed  time.Time
	inUse     bool
	mu        sync.RWMutex
}

// NewUDPConnectionPool creates a new UDP connection pool
func NewUDPConnectionPool(maxIdle int, maxLifetime time.Duration, logger log.Logger) *UDPConnectionPool {
	if maxIdle <= 0 {
		maxIdle = 10
	}
	if maxLifetime <= 0 {
		maxLifetime = 30 * time.Minute
	}

	pool := &UDPConnectionPool{
		connections: make(map[string]*UDPPooledConnection),
		maxIdle:     maxIdle,
		maxLifetime: maxLifetime,
		logger:      logger,
	}

	// Start cleanup goroutine
	go pool.cleanupRoutine()

	return pool
}

// GetConnection gets a connection from the pool or creates a new one
func (p *UDPConnectionPool) GetConnection(localAddr string) (*UDPPooledConnection, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Try to find an existing connection
	if conn, exists := p.connections[localAddr]; exists {
		conn.mu.Lock()
		if !conn.inUse && time.Since(conn.created) < p.maxLifetime {
			conn.inUse = true
			conn.lastUsed = time.Now()
			conn.mu.Unlock()
			return conn, nil
		}
		conn.mu.Unlock()

		// Connection is expired or in use, remove it
		conn.Close()
		delete(p.connections, localAddr)
	}

	// Create new connection
	conn, err := net.ListenPacket("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create UDP connection: %w", err)
	}

	pooledConn := &UDPPooledConnection{
		conn:      conn,
		localAddr: localAddr,
		created:   time.Now(),
		lastUsed:  time.Now(),
		inUse:     true,
	}

	p.connections[localAddr] = pooledConn
	return pooledConn, nil
}

// ReleaseConnection releases a connection back to the pool
func (p *UDPConnectionPool) ReleaseConnection(conn *UDPPooledConnection) {
	if conn == nil {
		return
	}

	conn.mu.Lock()
	conn.inUse = false
	conn.lastUsed = time.Now()
	conn.mu.Unlock()
}

// Close closes a pooled connection
func (c *UDPPooledConnection) Close() error {
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
func (p *UDPConnectionPool) cleanupRoutine() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()

		for addr, conn := range p.connections {
			conn.mu.RLock()
			expired := now.Sub(conn.created) > p.maxLifetime
			unused := !conn.inUse && now.Sub(conn.lastUsed) > 10*time.Minute
			conn.mu.RUnlock()

			if expired || unused {
				conn.Close()
				delete(p.connections, addr)
				if p.logger != nil {
					p.logger.Debugf("Cleaned up expired UDP connection: %s", addr)
				}
			}
		}
		p.mu.Unlock()
	}
}

// Close closes all connections in the pool
func (p *UDPConnectionPool) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for addr, conn := range p.connections {
		conn.Close()
		delete(p.connections, addr)
	}

	return nil
}

// UDPClient represents a UDP RADIUS client
type UDPClient struct {
	// Configuration
	serverAddr   string
	sharedSecret []byte
	timeout      time.Duration

	// Connection pooling
	connPool  *UDPConnectionPool
	localAddr string

	// Connection management
	conn net.PacketConn
	mu   sync.RWMutex

	// Statistics
	stats *UDPStatistics

	// Logger
	logger log.Logger
}

// UDPStatistics holds UDP client statistics
type UDPStatistics struct {
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

// NewUDPClient creates a new UDP RADIUS client
func NewUDPClient(serverAddr string, sharedSecret []byte, timeout time.Duration, logger log.Logger) (*UDPClient, error) {
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

	return &UDPClient{
		serverAddr:   serverAddr,
		sharedSecret: sharedSecret,
		timeout:      timeout,
		localAddr:    ":0", // Default to any local address
		stats:        &UDPStatistics{},
		logger:       logger,
	}, nil
}

// NewUDPClientWithPool creates a new UDP RADIUS client with connection pooling
func NewUDPClientWithPool(serverAddr string, sharedSecret []byte, timeout time.Duration, pool *UDPConnectionPool, logger log.Logger) (*UDPClient, error) {
	client, err := NewUDPClient(serverAddr, sharedSecret, timeout, logger)
	if err != nil {
		return nil, err
	}

	client.connPool = pool
	return client, nil
}

// SetLocalAddr sets the local address for the UDP client
func (c *UDPClient) SetLocalAddr(addr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localAddr = addr
}

// SendRequest sends a RADIUS request and waits for a response
func (c *UDPClient) SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
	if req == nil {
		return nil, fmt.Errorf("request packet cannot be nil")
	}

	startTime := time.Now()

	// Use connection pooling if available
	if c.connPool != nil {
		return c.sendRequestWithPool(ctx, req, startTime)
	}

	// Ensure connection is established
	if err := c.ensureConnection(); err != nil {
		return nil, fmt.Errorf("failed to establish connection: %w", err)
	}

	// Encode request packet
	requestData, err := req.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Send request
	response, err := c.sendWithTimeout(timeoutCtx, requestData, serverAddr)
	if err != nil {
		c.stats.mu.Lock()
		c.stats.Errors++
		c.stats.mu.Unlock()
		return nil, err
	}

	// Update statistics
	rtt := time.Since(startTime)
	c.stats.mu.Lock()
	c.stats.RequestsSent++
	c.stats.ResponsesReceived++
	c.stats.BytesSent += uint64(len(requestData))
	c.stats.BytesReceived += uint64(len(response))
	c.stats.LastRequest = startTime
	c.stats.LastResponse = time.Now()
	c.stats.AverageRTT = (c.stats.AverageRTT + rtt) / 2
	c.stats.mu.Unlock()

	// Decode response
	responsePacket, err := packet.Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Validate response
	if responsePacket.Identifier != req.Identifier {
		return nil, fmt.Errorf("response identifier mismatch: expected %d, got %d",
			req.Identifier, responsePacket.Identifier)
	}

	return responsePacket, nil
}

// sendRequestWithPool sends a request using connection pooling
func (c *UDPClient) sendRequestWithPool(ctx context.Context, req *packet.Packet, startTime time.Time) (*packet.Packet, error) {
	// Get connection from pool
	pooledConn, err := c.connPool.GetConnection(c.localAddr)
	if err != nil {
		c.stats.mu.Lock()
		c.stats.Errors++
		c.stats.mu.Unlock()
		return nil, fmt.Errorf("failed to get connection from pool: %w", err)
	}
	defer c.connPool.ReleaseConnection(pooledConn)

	// Encode request packet
	requestData, err := req.Encode()
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", c.serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve server address: %w", err)
	}

	// Create timeout context
	timeoutCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	// Send request using pooled connection
	response, err := c.sendWithPooledConnection(timeoutCtx, requestData, serverAddr, pooledConn)
	if err != nil {
		c.stats.mu.Lock()
		c.stats.Errors++
		c.stats.mu.Unlock()
		return nil, err
	}

	// Update statistics
	rtt := time.Since(startTime)
	c.stats.mu.Lock()
	c.stats.RequestsSent++
	c.stats.ResponsesReceived++
	c.stats.BytesSent += uint64(len(requestData))
	c.stats.BytesReceived += uint64(len(response))
	c.stats.LastRequest = startTime
	c.stats.LastResponse = time.Now()
	c.stats.AverageRTT = (c.stats.AverageRTT + rtt) / 2
	c.stats.ConnectionReuses++
	c.stats.mu.Unlock()

	// Decode response
	responsePacket, err := packet.Decode(response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	// Validate response
	if responsePacket.Identifier != req.Identifier {
		return nil, fmt.Errorf("response identifier mismatch: expected %d, got %d",
			req.Identifier, responsePacket.Identifier)
	}

	return responsePacket, nil
}

// sendWithPooledConnection sends a request using a pooled connection
func (c *UDPClient) sendWithPooledConnection(ctx context.Context, data []byte, serverAddr *net.UDPAddr, pooledConn *UDPPooledConnection) ([]byte, error) {
	pooledConn.mu.RLock()
	conn := pooledConn.conn
	pooledConn.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("pooled connection is nil")
	}

	// Send request
	_, err := conn.WriteTo(data, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Create response channel
	responseChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	// Start goroutine to read response
	go func() {
		buffer := make([]byte, 4096)

		// Set read deadline
		if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			errorChan <- fmt.Errorf("failed to set read deadline: %w", err)
			return
		}

		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			errorChan <- fmt.Errorf("failed to read response: %w", err)
			return
		}

		// Verify response is from expected server
		if addr.String() != serverAddr.String() {
			errorChan <- fmt.Errorf("response from unexpected server: %s", addr.String())
			return
		}

		responseChan <- buffer[:n]
	}()

	// Wait for response or timeout
	select {
	case response := <-responseChan:
		return response, nil
	case err := <-errorChan:
		return nil, err
	case <-ctx.Done():
		c.stats.mu.Lock()
		c.stats.Timeouts++
		c.stats.mu.Unlock()
		return nil, fmt.Errorf("request timeout: %w", ctx.Err())
	}
}

// ensureConnection ensures that a UDP connection is established
func (c *UDPClient) ensureConnection() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		return nil
	}

	// Create UDP connection
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		c.stats.mu.Lock()
		c.stats.ConnectionFailures++
		c.stats.mu.Unlock()
		return fmt.Errorf("failed to create UDP connection: %w", err)
	}

	c.conn = conn
	c.stats.mu.Lock()
	c.stats.ConnectionAttempts++
	c.stats.mu.Unlock()

	c.logger.Debugf("UDP connection established for server %s", c.serverAddr)
	return nil
}

// sendWithTimeout sends a request with timeout
func (c *UDPClient) sendWithTimeout(ctx context.Context, data []byte, serverAddr *net.UDPAddr) ([]byte, error) {
	c.mu.RLock()
	conn := c.conn
	c.mu.RUnlock()

	if conn == nil {
		return nil, fmt.Errorf("not connected")
	}

	// Send request
	_, err := conn.WriteTo(data, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}

	// Create response channel
	responseChan := make(chan []byte, 1)
	errorChan := make(chan error, 1)

	// Start goroutine to read response
	go func() {
		buffer := make([]byte, 4096)

		// Set read deadline
		if err := conn.SetReadDeadline(time.Now().Add(c.timeout)); err != nil {
			errorChan <- fmt.Errorf("failed to set read deadline: %w", err)
			return
		}

		n, addr, err := conn.ReadFrom(buffer)
		if err != nil {
			errorChan <- fmt.Errorf("failed to read response: %w", err)
			return
		}

		// Verify response is from expected server
		if addr.String() != serverAddr.String() {
			errorChan <- fmt.Errorf("response from unexpected server: %s", addr.String())
			return
		}

		responseChan <- buffer[:n]
	}()

	// Wait for response or timeout
	select {
	case response := <-responseChan:
		return response, nil
	case err := <-errorChan:
		return nil, err
	case <-ctx.Done():
		c.stats.mu.Lock()
		c.stats.Timeouts++
		c.stats.mu.Unlock()
		return nil, fmt.Errorf("request timeout: %w", ctx.Err())
	}
}

// Close closes the UDP client
func (c *UDPClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	var err error

	// Close regular connection if exists
	if c.conn != nil {
		err = c.conn.Close()
		c.conn = nil

		c.stats.mu.Lock()
		c.stats.DisconnectionCount++
		c.stats.mu.Unlock()

		c.logger.Debug("UDP connection closed")
	}

	// Note: We don't close the connection pool here as it may be shared
	// The pool should be closed separately by the owner

	return err
}

// GetStatistics returns client statistics
func (c *UDPClient) GetStatistics() *Statistics {
	c.stats.mu.RLock()
	defer c.stats.mu.RUnlock()

	return &Statistics{
		RequestsSent:        int64(c.stats.RequestsSent),
		ResponsesReceived:   int64(c.stats.ResponsesReceived),
		Timeouts:            int64(c.stats.Timeouts),
		Errors:              int64(c.stats.Errors),
		ConnectionsTotal:    int64(c.stats.ConnectionAttempts),
		ConnectionsFailures: int64(c.stats.ConnectionFailures),
		AverageRTT:          c.stats.AverageRTT,
	}
}

// IsConnected returns true if the client has an active connection
func (c *UDPClient) IsConnected() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.conn != nil
}

// GetServerAddress returns the server address
func (c *UDPClient) GetServerAddress() string {
	return c.serverAddr
}

// SetTimeout sets the request timeout
func (c *UDPClient) SetTimeout(timeout time.Duration) {
	c.timeout = timeout
}

// GetTimeout returns the current timeout
func (c *UDPClient) GetTimeout() time.Duration {
	return c.timeout
}
