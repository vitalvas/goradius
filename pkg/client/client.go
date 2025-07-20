package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// Client represents a RADIUS client
type Client interface {
	// SendRequest sends a RADIUS request and waits for a response
	SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error)

	// SendRequestWithRetry sends a request with retry logic
	SendRequestWithRetry(ctx context.Context, req *packet.Packet, maxRetries int) (*packet.Packet, error)

	// GetStatistics returns client statistics
	GetStatistics() *Statistics

	// Close closes the client and releases resources
	Close() error
}

// Config holds client configuration
type Config struct {
	// Server configuration
	Servers []ServerConfig

	// Transport settings
	Transport TransportType
	Timeout   time.Duration

	// TLS settings (for TCP with TLS)
	TLSConfig *tls.Config

	// Retry settings
	MaxRetries    int
	RetryInterval time.Duration

	// Failover settings
	FailoverTimeout     time.Duration
	HealthCheckInterval time.Duration

	// Authentication settings
	SharedSecret []byte

	// Logger
	Logger log.Logger `yaml:"-"`
}

// ServerConfig holds configuration for a single server
type ServerConfig struct {
	Address      string
	Port         int
	SharedSecret []byte
	Priority     int
	Weight       int
	Timeout      time.Duration
}

// TransportType defines the transport protocol
type TransportType string

const (
	TransportUDP TransportType = "udp"
	TransportTCP TransportType = "tcp"
)

// Statistics holds client statistics
type Statistics struct {
	// Request statistics
	RequestsSent      int64
	ResponsesReceived int64
	Timeouts          int64
	Errors            int64
	Retries           int64

	// Failover statistics
	FailoverCount    int64
	ActiveServer     string
	ServerStatistics map[string]*ServerStatistics

	// Timing statistics
	AverageRTT time.Duration
	MinRTT     time.Duration
	MaxRTT     time.Duration

	// Connection statistics
	ConnectionsActive   int64
	ConnectionsTotal    int64
	ConnectionsFailures int64

	// Bytes transferred
	BytesSent     int64
	BytesReceived int64

	// Timing
	LastRequest  time.Time
	LastResponse time.Time
	StartTime    time.Time
}

// ServerStatistics holds statistics for a single server
type ServerStatistics struct {
	Address           string
	Active            bool
	Healthy           bool
	RequestsSent      int64
	ResponsesReceived int64
	Timeouts          int64
	Errors            int64
	AverageRTT        time.Duration
	LastRequest       time.Time
	LastResponse      time.Time
	LastHealthCheck   time.Time
	FailureCount      int64
	RecoveryCount     int64
}

// RADIUSClient implements the Client interface
type RADIUSClient struct {
	config *Config

	// Server management
	servers      []ServerConfig
	serverStates map[string]*ServerState

	// Transport clients
	udpClients map[string]*UDPClient
	tcpClients map[string]*TCPClient

	// Request correlation
	requestID       uint32
	pendingRequests map[uint8]*PendingRequest

	// Statistics
	stats *Statistics

	// Health checking
	healthChecker *HealthChecker

	// Synchronization
	mu sync.RWMutex

	// Lifecycle
	started bool
	closed  bool
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Logger
	logger log.Logger
}

// ServerState tracks the state of a server
type ServerState struct {
	config       ServerConfig
	healthy      bool
	lastCheck    time.Time
	failureCount int64
	mu           sync.RWMutex
}

// PendingRequest tracks a pending request
type PendingRequest struct {
	ID        uint8
	Packet    *packet.Packet
	Timestamp time.Time
	Done      chan *packet.Packet
	Error     chan error
}

// HealthChecker performs health checks on servers
type HealthChecker struct {
	client   *RADIUSClient
	interval time.Duration
	timeout  time.Duration
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup
}

// DefaultConfig returns a default client configuration
func DefaultConfig() *Config {
	return &Config{
		Transport:           TransportUDP,
		Timeout:             30 * time.Second,
		MaxRetries:          3,
		RetryInterval:       1 * time.Second,
		FailoverTimeout:     5 * time.Second,
		HealthCheckInterval: 30 * time.Second,
		Logger:              log.NewDefaultLogger(),
	}
}

// NewClient creates a new RADIUS client
func NewClient(config *Config) (Client, error) {
	if config == nil {
		config = DefaultConfig()
	}

	// Validate configuration
	if err := validateConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	client := &RADIUSClient{
		config:          config,
		servers:         config.Servers,
		serverStates:    make(map[string]*ServerState),
		udpClients:      make(map[string]*UDPClient),
		tcpClients:      make(map[string]*TCPClient),
		pendingRequests: make(map[uint8]*PendingRequest),
		stats:           NewStatistics(),
		ctx:             ctx,
		cancel:          cancel,
		logger:          config.Logger,
	}

	// Initialize server states
	for _, server := range config.Servers {
		key := fmt.Sprintf("%s:%d", server.Address, server.Port)
		client.serverStates[key] = &ServerState{
			config:  server,
			healthy: true,
		}
	}

	// Initialize health checker
	client.healthChecker = NewHealthChecker(client, config.HealthCheckInterval, config.Timeout)

	return client, nil
}

// validateConfig validates the client configuration
func validateConfig(config *Config) error {
	if len(config.Servers) == 0 {
		return fmt.Errorf("at least one server must be configured")
	}

	for i, server := range config.Servers {
		if server.Address == "" {
			return fmt.Errorf("server %d: address cannot be empty", i)
		}
		if server.Port <= 0 || server.Port > 65535 {
			return fmt.Errorf("server %d: invalid port %d", i, server.Port)
		}
		if len(server.SharedSecret) == 0 && len(config.SharedSecret) == 0 {
			return fmt.Errorf("server %d: shared secret cannot be empty", i)
		}
	}

	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}

	if config.MaxRetries < 0 {
		config.MaxRetries = 3
	}

	if config.RetryInterval <= 0 {
		config.RetryInterval = 1 * time.Second
	}

	if config.Logger == nil {
		config.Logger = log.NewDefaultLogger()
	}

	return nil
}

// Start starts the client
func (c *RADIUSClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.started {
		return fmt.Errorf("client already started")
	}

	// Initialize transport clients
	if err := c.initializeTransportClients(); err != nil {
		return fmt.Errorf("failed to initialize transport clients: %w", err)
	}

	// Start health checker
	if err := c.healthChecker.Start(); err != nil {
		return fmt.Errorf("failed to start health checker: %w", err)
	}

	c.started = true
	c.stats.StartTime = time.Now()

	c.logger.Info("RADIUS client started")
	return nil
}

// initializeTransportClients initializes transport-specific clients
func (c *RADIUSClient) initializeTransportClients() error {
	for _, server := range c.servers {
		serverAddr := fmt.Sprintf("%s:%d", server.Address, server.Port)
		secret := server.SharedSecret
		if len(secret) == 0 {
			secret = c.config.SharedSecret
		}
		timeout := server.Timeout
		if timeout == 0 {
			timeout = c.config.Timeout
		}

		switch c.config.Transport {
		case TransportUDP:
			client, err := NewUDPClient(serverAddr, secret, timeout, c.logger)
			if err != nil {
				return fmt.Errorf("failed to create UDP client for %s: %w", serverAddr, err)
			}
			c.udpClients[serverAddr] = client

		case TransportTCP:
			client, err := NewTCPClientWithTLS(serverAddr, secret, timeout, c.config.TLSConfig, c.logger)
			if err != nil {
				return fmt.Errorf("failed to create TCP client for %s: %w", serverAddr, err)
			}
			c.tcpClients[serverAddr] = client

		default:
			return fmt.Errorf("unsupported transport type: %s", c.config.Transport)
		}
	}

	return nil
}

// SendRequest sends a RADIUS request and waits for a response
func (c *RADIUSClient) SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
	return c.SendRequestWithRetry(ctx, req, c.config.MaxRetries)
}

// SendRequestWithRetry sends a request with retry logic
func (c *RADIUSClient) SendRequestWithRetry(ctx context.Context, req *packet.Packet, maxRetries int) (*packet.Packet, error) {
	if req == nil {
		return nil, fmt.Errorf("request packet cannot be nil")
	}

	// Ensure client is started
	if !c.started {
		if err := c.Start(); err != nil {
			return nil, fmt.Errorf("failed to start client: %w", err)
		}
	}

	// Prepare request
	if err := c.prepareRequest(req); err != nil {
		return nil, fmt.Errorf("failed to prepare request: %w", err)
	}

	atomic.AddInt64(&c.stats.RequestsSent, 1)
	c.stats.LastRequest = time.Now()

	var lastError error

	// Try each server with retries
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			atomic.AddInt64(&c.stats.Retries, 1)

			// Wait before retry
			select {
			case <-time.After(c.config.RetryInterval):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		// Get active server
		serverAddr, client := c.getActiveServer()
		if client == nil {
			return nil, fmt.Errorf("no healthy servers available")
		}

		// Send request
		start := time.Now()
		response, err := c.sendRequestToServer(ctx, req, serverAddr, client)

		if err != nil {
			lastError = err
			c.logger.Warnf("Request failed to server %s (attempt %d/%d): %v",
				serverAddr, attempt+1, maxRetries+1, err)

			// Mark server as unhealthy on certain errors
			if isServerError(err) {
				c.markServerUnhealthy(serverAddr)
			}

			continue
		}

		// Success
		rtt := time.Since(start)
		c.updateStatistics(serverAddr, rtt, true)

		atomic.AddInt64(&c.stats.ResponsesReceived, 1)
		c.stats.LastResponse = time.Now()

		return response, nil
	}

	atomic.AddInt64(&c.stats.Errors, 1)
	return nil, fmt.Errorf("request failed after %d attempts: %w", maxRetries+1, lastError)
}

// prepareRequest prepares a request packet
func (c *RADIUSClient) prepareRequest(req *packet.Packet) error {
	// Set request identifier
	req.Identifier = c.generateRequestID()

	// Generate request authenticator
	if _, err := rand.Read(req.Authenticator[:]); err != nil {
		return fmt.Errorf("failed to generate request authenticator: %w", err)
	}

	// Calculate packet length
	req.Length = packet.PacketHeaderLength
	for _, attr := range req.Attributes {
		req.Length += uint16(attr.Length)
	}

	return nil
}

// generateRequestID generates a unique request identifier
func (c *RADIUSClient) generateRequestID() uint8 {
	return uint8(atomic.AddUint32(&c.requestID, 1))
}

// getActiveServer returns the active server and client
func (c *RADIUSClient) getActiveServer() (string, interface{}) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Try to find a healthy server
	for _, server := range c.servers {
		serverAddr := fmt.Sprintf("%s:%d", server.Address, server.Port)

		if state, exists := c.serverStates[serverAddr]; exists && state.healthy {
			switch c.config.Transport {
			case TransportUDP:
				if client, exists := c.udpClients[serverAddr]; exists {
					return serverAddr, client
				}
			case TransportTCP:
				if client, exists := c.tcpClients[serverAddr]; exists {
					return serverAddr, client
				}
			}
		}
	}

	return "", nil
}

// sendRequestToServer sends a request to a specific server
func (c *RADIUSClient) sendRequestToServer(ctx context.Context, req *packet.Packet, _ string, client interface{}) (*packet.Packet, error) {
	switch c.config.Transport {
	case TransportUDP:
		if udpClient, ok := client.(*UDPClient); ok {
			return udpClient.SendRequest(ctx, req)
		}
	case TransportTCP:
		if tcpClient, ok := client.(*TCPClient); ok {
			return tcpClient.SendRequest(ctx, req)
		}
	}

	return nil, fmt.Errorf("invalid client type for transport %s", c.config.Transport)
}

// markServerUnhealthy marks a server as unhealthy
func (c *RADIUSClient) markServerUnhealthy(serverAddr string) {
	if state, exists := c.serverStates[serverAddr]; exists {
		state.mu.Lock()
		state.healthy = false
		state.failureCount++
		state.mu.Unlock()

		c.logger.Warnf("Marked server %s as unhealthy", serverAddr)
	}
}

// updateStatistics updates client statistics
func (c *RADIUSClient) updateStatistics(serverAddr string, rtt time.Duration, success bool) {
	// Update global statistics
	if c.stats.MinRTT == 0 || rtt < c.stats.MinRTT {
		c.stats.MinRTT = rtt
	}
	if rtt > c.stats.MaxRTT {
		c.stats.MaxRTT = rtt
	}

	// Update average RTT
	if c.stats.AverageRTT == 0 {
		c.stats.AverageRTT = rtt
	} else {
		c.stats.AverageRTT = (c.stats.AverageRTT + rtt) / 2
	}

	// Update server statistics
	if c.stats.ServerStatistics == nil {
		c.stats.ServerStatistics = make(map[string]*ServerStatistics)
	}

	if _, exists := c.stats.ServerStatistics[serverAddr]; !exists {
		c.stats.ServerStatistics[serverAddr] = &ServerStatistics{
			Address: serverAddr,
		}
	}

	serverStats := c.stats.ServerStatistics[serverAddr]
	atomic.AddInt64(&serverStats.RequestsSent, 1)

	if success {
		atomic.AddInt64(&serverStats.ResponsesReceived, 1)
		serverStats.LastResponse = time.Now()
		serverStats.AverageRTT = (serverStats.AverageRTT + rtt) / 2
	} else {
		atomic.AddInt64(&serverStats.Errors, 1)
	}

	serverStats.LastRequest = time.Now()
}

// GetStatistics returns client statistics
func (c *RADIUSClient) GetStatistics() *Statistics {
	return &Statistics{
		RequestsSent:        atomic.LoadInt64(&c.stats.RequestsSent),
		ResponsesReceived:   atomic.LoadInt64(&c.stats.ResponsesReceived),
		Timeouts:            atomic.LoadInt64(&c.stats.Timeouts),
		Errors:              atomic.LoadInt64(&c.stats.Errors),
		Retries:             atomic.LoadInt64(&c.stats.Retries),
		FailoverCount:       atomic.LoadInt64(&c.stats.FailoverCount),
		ActiveServer:        c.stats.ActiveServer,
		ServerStatistics:    c.copyServerStatistics(),
		AverageRTT:          c.stats.AverageRTT,
		MinRTT:              c.stats.MinRTT,
		MaxRTT:              c.stats.MaxRTT,
		ConnectionsActive:   atomic.LoadInt64(&c.stats.ConnectionsActive),
		ConnectionsTotal:    atomic.LoadInt64(&c.stats.ConnectionsTotal),
		ConnectionsFailures: atomic.LoadInt64(&c.stats.ConnectionsFailures),
		BytesSent:           atomic.LoadInt64(&c.stats.BytesSent),
		BytesReceived:       atomic.LoadInt64(&c.stats.BytesReceived),
		LastRequest:         c.stats.LastRequest,
		LastResponse:        c.stats.LastResponse,
		StartTime:           c.stats.StartTime,
	}
}

// copyServerStatistics creates a copy of server statistics
func (c *RADIUSClient) copyServerStatistics() map[string]*ServerStatistics {
	result := make(map[string]*ServerStatistics)

	for addr, stats := range c.stats.ServerStatistics {
		result[addr] = &ServerStatistics{
			Address:           stats.Address,
			Active:            stats.Active,
			Healthy:           stats.Healthy,
			RequestsSent:      atomic.LoadInt64(&stats.RequestsSent),
			ResponsesReceived: atomic.LoadInt64(&stats.ResponsesReceived),
			Timeouts:          atomic.LoadInt64(&stats.Timeouts),
			Errors:            atomic.LoadInt64(&stats.Errors),
			AverageRTT:        stats.AverageRTT,
			LastRequest:       stats.LastRequest,
			LastResponse:      stats.LastResponse,
			LastHealthCheck:   stats.LastHealthCheck,
			FailureCount:      atomic.LoadInt64(&stats.FailureCount),
			RecoveryCount:     atomic.LoadInt64(&stats.RecoveryCount),
		}
	}

	return result
}

// Close closes the client and releases resources
func (c *RADIUSClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return nil
	}

	c.cancel()
	c.wg.Wait()

	// Close health checker
	if c.healthChecker != nil {
		c.healthChecker.Stop()
	}

	// Close transport clients
	if c.udpClients != nil {
		for _, client := range c.udpClients {
			client.Close()
		}
	}
	if c.tcpClients != nil {
		for _, client := range c.tcpClients {
			client.Disconnect()
		}
	}

	c.closed = true
	if c.logger != nil {
		c.logger.Info("RADIUS client closed")
	}

	return nil
}

// NewStatistics creates new client statistics
func NewStatistics() *Statistics {
	return &Statistics{
		ServerStatistics: make(map[string]*ServerStatistics),
	}
}

// isServerError checks if an error indicates a server problem
func isServerError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors that indicate server problems
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}

	// Check for common server errors
	errStr := err.Error()
	return strings.Contains(errStr, "connection refused") ||
		strings.Contains(errStr, "connection reset") ||
		strings.Contains(errStr, "no route to host") ||
		strings.Contains(errStr, "network unreachable")
}
