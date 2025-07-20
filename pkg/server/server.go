package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// Server represents a RADIUS server
type Server struct {
	// Configuration
	config *Config

	// Network listeners
	udpListeners map[string]*UDPListener
	tcpListeners map[string]*TCPListener
	mu           sync.RWMutex

	// Handler for processing requests
	handler Handler

	// Server state
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Logger
	logger log.Logger

	// Statistics
	stats *Statistics
}

// Config holds server configuration
type Config struct {
	// Network bindings
	Bindings []Binding

	// Request handling
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	MaxRequestSize int

	// Worker pool
	Workers int

	// Logging
	Logger log.Logger
}

// Binding represents a network binding configuration
type Binding struct {
	// Network address
	Address string
	Port    int

	// IP version (4, 6, or 0 for dual-stack)
	IPVersion int

	// Transport type (UDP, TCP)
	Transport TransportType

	// TLS configuration (for TCP with TLS)
	TLSConfig *tls.Config

	// Client configuration
	Clients []ClientConfig
}

// ClientConfig represents allowed client configuration
type ClientConfig struct {
	// IP addresses or CIDR blocks
	Networks []string

	// Shared secret
	Secret string

	// Client name (optional)
	Name string
}

// Handler interface for processing RADIUS requests
type Handler interface {
	// HandleRequest processes a RADIUS request and returns a response
	HandleRequest(ctx context.Context, req *Request) (*Response, error)

	// GetSharedSecret returns the shared secret for a client
	GetSharedSecret(clientAddr net.Addr) ([]byte, error)
}

// Request represents an incoming RADIUS request
type Request struct {
	// Network information
	ClientAddr net.Addr
	ServerAddr net.Addr

	// RADIUS packet
	Packet *packet.Packet

	// Client configuration
	Client *ClientConfig

	// Timing
	ReceivedAt time.Time
}

// Response represents a RADIUS response
type Response struct {
	// RADIUS packet
	Packet *packet.Packet

	// Whether to send the response
	Send bool
}

// UDPListener handles UDP connections for a specific binding
type UDPListener struct {
	// Configuration
	binding Binding
	config  *Config

	// Network connection
	conn net.PacketConn

	// Handler
	handler Handler

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

// Statistics holds server statistics
type Statistics struct {
	mu sync.RWMutex

	// Request counts
	TotalRequests   uint64
	TotalResponses  uint64
	InvalidRequests uint64
	DroppedRequests uint64
	TimeoutRequests uint64

	// Timing
	StartTime      time.Time
	AverageLatency time.Duration
	MaxLatency     time.Duration

	// Per-service statistics
}

// ServiceStatistics holds statistics for a specific service
type ServiceStatistics struct {
	Requests  uint64
	Responses uint64
	Errors    uint64
	Latency   time.Duration
}

// ListenerStatistics holds statistics for a specific listener
type ListenerStatistics struct {
	mu sync.RWMutex

	// Network statistics
	BytesReceived uint64
	BytesSent     uint64
	Connections   uint64

	// Request statistics
	Requests  uint64
	Responses uint64
	Errors    uint64

	// Timing
	LastRequest time.Time
}

// DefaultConfig returns a default server configuration
func DefaultConfig() *Config {
	return &Config{
		Bindings: []Binding{
			{
				Address:   "0.0.0.0",
				Port:      1812,
				IPVersion: 0, // Dual-stack
				Transport: TransportUDP,
			},
			{
				Address:   "0.0.0.0",
				Port:      1813,
				IPVersion: 0, // Dual-stack
				Transport: TransportUDP,
			},
		},
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		MaxRequestSize: 4096,
		Workers:        10,
		Logger:         log.NewDefaultLogger(),
	}
}

// NewServer creates a new RADIUS server
func NewServer(config *Config, handler Handler) (*Server, error) {
	if config == nil {
		config = DefaultConfig()
	}

	if handler == nil {
		return nil, fmt.Errorf("handler cannot be nil")
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		config:       config,
		udpListeners: make(map[string]*UDPListener),
		tcpListeners: make(map[string]*TCPListener),
		handler:      handler,
		ctx:          ctx,
		cancel:       cancel,
		logger:       config.Logger,
		stats:        NewStatistics(),
	}, nil
}

// Start starts the server and begins listening
func (s *Server) Start() error {
	s.logger.Info("Starting RADIUS server")

	// Start listeners for each binding
	for i, binding := range s.config.Bindings {
		listenerKey := fmt.Sprintf("%s:%d:%s", binding.Address, binding.Port, binding.Transport)

		err := s.createListener(binding, listenerKey, i)
		if err != nil {
			s.logger.Errorf("Failed to create listener for %s: %v", listenerKey, err)
			s.Stop()
			return fmt.Errorf("failed to create listener for %s: %w", listenerKey, err)
		}

		s.logger.Infof("Started %s listener on %s:%d", binding.Transport, binding.Address, binding.Port)
	}

	s.stats.StartTime = time.Now()
	s.logger.Info("RADIUS server started successfully")
	return nil
}

// Stop stops the server gracefully
func (s *Server) Stop() error {
	s.logger.Info("Stopping RADIUS server")

	// Cancel context to signal shutdown
	s.cancel()

	// Stop all listeners
	s.mu.RLock()
	for _, listener := range s.udpListeners {
		listener.Stop()
	}
	for _, listener := range s.tcpListeners {
		listener.Stop()
	}
	s.mu.RUnlock()

	// Wait for all goroutines to finish
	s.wg.Wait()

	s.logger.Info("RADIUS server stopped")
	return nil
}

// GetStatistics returns server statistics
func (s *Server) GetStatistics() *Statistics {
	return s.stats
}

// createListener creates a listener for a binding based on transport type
func (s *Server) createListener(binding Binding, listenerKey string, index int) error {
	switch binding.Transport {
	case TransportUDP:
		return s.createUDPListener(binding, listenerKey, index)
	case TransportTCP:
		return s.createTCPListener(binding, listenerKey, index)
	default:
		return fmt.Errorf("unsupported transport type: %s", binding.Transport)
	}
}

// createUDPListener creates a UDP listener for a binding
func (s *Server) createUDPListener(binding Binding, listenerKey string, index int) error {
	// Determine network type based on IP version
	var network string
	switch binding.IPVersion {
	case 4:
		network = "udp4"
	case 6:
		network = "udp6"
	default:
		network = "udp" // Dual-stack
	}

	// Create listen address
	var listenAddr string
	if binding.IPVersion == 6 && !strings.HasPrefix(binding.Address, "[") {
		// IPv6 addresses need brackets when combined with port
		listenAddr = fmt.Sprintf("[%s]:%d", binding.Address, binding.Port)
	} else {
		listenAddr = fmt.Sprintf("%s:%d", binding.Address, binding.Port)
	}

	// Create UDP connection
	conn, err := net.ListenPacket(network, listenAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", listenAddr, err)
	}

	ctx, cancel := context.WithCancel(s.ctx)

	listener := &UDPListener{
		binding: binding,
		config:  s.config,
		conn:    conn,
		handler: s.handler,
		workers: make(chan struct{}, s.config.Workers),
		logger:  s.logger,
		ctx:     ctx,
		cancel:  cancel,
		stats:   NewListenerStatistics(),
	}

	// Initialize worker pool
	for i := 0; i < s.config.Workers; i++ {
		listener.workers <- struct{}{}
	}

	// Store listener
	s.mu.Lock()
	s.udpListeners[listenerKey] = listener
	s.mu.Unlock()

	// Start listening
	s.wg.Add(1)
	go func(l *UDPListener, idx int) {
		defer s.wg.Done()
		if err := l.Listen(); err != nil {
			s.logger.Errorf("UDP listener %d failed: %v", idx, err)
		}
	}(listener, index)

	return nil
}

// createTCPListener creates a TCP listener for a binding
func (s *Server) createTCPListener(binding Binding, listenerKey string, index int) error {
	// Create TCP listener
	listener, err := NewTCPListener(s.ctx, binding, s.config, s.handler, s.logger)
	if err != nil {
		return fmt.Errorf("failed to create TCP listener: %w", err)
	}

	// Store listener
	s.mu.Lock()
	s.tcpListeners[listenerKey] = listener
	s.mu.Unlock()

	// Start listening
	s.wg.Add(1)
	go func(l *TCPListener, idx int) {
		defer s.wg.Done()
		if err := l.Listen(); err != nil {
			s.logger.Errorf("TCP listener %d failed: %v", idx, err)
		}
	}(listener, index)

	return nil
}

// NewStatistics creates new server statistics
func NewStatistics() *Statistics {
	return &Statistics{
		StartTime: time.Now(),
	}
}

// NewListenerStatistics creates new listener statistics
func NewListenerStatistics() *ListenerStatistics {
	return &ListenerStatistics{}
}

// UpdateRequestStats updates request statistics
func (s *Statistics) UpdateRequestStats(latency time.Duration, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.TotalRequests++

	if success {
		s.TotalResponses++
	}

	// Update latency statistics
	if latency > s.MaxLatency {
		s.MaxLatency = latency
	}

}

// UpdateListenerStats updates listener statistics
func (l *ListenerStatistics) UpdateRequestStats(bytesReceived, bytesSent uint64, success bool) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.BytesReceived += bytesReceived
	l.BytesSent += bytesSent
	l.Requests++
	l.LastRequest = time.Now()

	if success {
		l.Responses++
	} else {
		l.Errors++
	}
}
