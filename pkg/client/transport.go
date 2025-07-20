package client

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// TransportManager manages multiple transport clients and provides transport selection
type TransportManager struct {
	transports map[TransportType]TransportClient
	pools      *ConnectionPools
	config     *TransportConfig
	logger     log.Logger
	mu         sync.RWMutex
}

// TransportClient represents a unified interface for all transport clients
type TransportClient interface {
	SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error)
	GetStatistics() *Statistics
	Close() error
	IsConnected() bool
	GetServerAddress() string
	SetTimeout(timeout time.Duration)
	GetTimeout() time.Duration
}

// TransportConfig holds configuration for transport selection and management
type TransportConfig struct {
	// Default transport type
	DefaultTransport TransportType

	// Transport priorities (higher number = higher priority)
	TransportPriorities map[TransportType]int

	// Failover configuration
	EnableFailover  bool
	FailoverTimeout time.Duration
	FailoverRetries int

	// Connection pooling
	EnablePooling bool
	PoolConfig    *ConnectionPoolConfig

	// Transport-specific settings
	UDPConfig *UDPTransportConfig
	TCPConfig *TCPTransportConfig

	// Load balancing
	LoadBalancing LoadBalancingStrategy
}

// LoadBalancingStrategy defines how to distribute requests across transports
type LoadBalancingStrategy string

const (
	LoadBalancingRoundRobin   LoadBalancingStrategy = "round_robin"
	LoadBalancingWeighted     LoadBalancingStrategy = "weighted"
	LoadBalancingLeastLatency LoadBalancingStrategy = "least_latency"
	LoadBalancingFailover     LoadBalancingStrategy = "failover"
	LoadBalancingRandom       LoadBalancingStrategy = "random"
)

// UDPTransportConfig holds UDP-specific configuration
type UDPTransportConfig struct {
	LocalAddr       string
	MaxPacketSize   int
	ReceiveBuffer   int
	SendBuffer      int
	EnableMulticast bool
	MulticastGroup  string
}

// TCPTransportConfig holds TCP-specific configuration
type TCPTransportConfig struct {
	KeepAlive       bool
	KeepAlivePeriod time.Duration
	NoDelay         bool
	MaxIdleTime     time.Duration
	ConnectTimeout  time.Duration
	ReadBuffer      int
	WriteBuffer     int
}

// EnhancedTLSConfig provides enhanced TLS configuration options
type EnhancedTLSConfig struct {
	// Certificate configuration
	CertFile   string
	KeyFile    string
	CAFile     string
	CACertData []byte

	// TLS settings
	MinVersion          uint16
	MaxVersion          uint16
	CipherSuites        []uint16
	PreferServerCiphers bool
	InsecureSkipVerify  bool
	ServerName          string

	// Client certificate authentication
	ClientAuth     string // "none", "request", "require", "verify_if_given", "require_and_verify"
	ClientCertFile string
	ClientKeyFile  string

	// Session settings
	SessionTicketsDisabled bool
	SessionCacheSize       int

	// OCSP and certificate validation
	EnableOCSP          bool
	OCSPStapling        bool
	CertificateLifetime time.Duration
}

// ConnectionPoolConfig holds configuration for connection pooling
type ConnectionPoolConfig struct {
	// Pool sizes
	UDPMaxIdle int
	TCPMaxIdle int

	// Lifetimes
	UDPMaxLifetime time.Duration
	TCPMaxLifetime time.Duration

	// Cleanup intervals
	CleanupInterval time.Duration

	// Pool behavior
	EnablePreallocation bool
	PreallocationSize   int
	EnableMetrics       bool
}

// ConnectionPools manages connection pools for all transports
type ConnectionPools struct {
	UDP    *UDPConnectionPool
	TCP    *TCPConnectionPool
	logger log.Logger
	// mu     sync.RWMutex // TODO: implement if ConnectionPools needs concurrent access protection
}

// NewTransportManager creates a new transport manager
func NewTransportManager(config *TransportConfig, logger log.Logger) *TransportManager {
	if config == nil {
		config = DefaultTransportConfig()
	}

	if logger == nil {
		logger = log.NewDefaultLogger()
	}

	tm := &TransportManager{
		transports: make(map[TransportType]TransportClient),
		config:     config,
		logger:     logger,
	}

	// Initialize connection pools if enabled
	if config.EnablePooling {
		tm.pools = tm.initializeConnectionPools(config.PoolConfig)
	}

	return tm
}

// DefaultTransportConfig returns a default transport configuration
func DefaultTransportConfig() *TransportConfig {
	return &TransportConfig{
		DefaultTransport: TransportUDP,
		TransportPriorities: map[TransportType]int{
			TransportUDP: 1,
			TransportTCP: 2,
		},
		EnableFailover:  true,
		FailoverTimeout: 5 * time.Second,
		FailoverRetries: 2,
		EnablePooling:   true,
		PoolConfig:      DefaultConnectionPoolConfig(),
		UDPConfig:       DefaultUDPTransportConfig(),
		TCPConfig:       DefaultTCPTransportConfig(),
		LoadBalancing:   LoadBalancingFailover,
	}
}

// DefaultConnectionPoolConfig returns default connection pool configuration
func DefaultConnectionPoolConfig() *ConnectionPoolConfig {
	return &ConnectionPoolConfig{
		UDPMaxIdle:          10,
		TCPMaxIdle:          5,
		UDPMaxLifetime:      30 * time.Minute,
		TCPMaxLifetime:      10 * time.Minute,
		CleanupInterval:     2 * time.Minute,
		EnablePreallocation: false,
		PreallocationSize:   2,
		EnableMetrics:       true,
	}
}

// DefaultUDPTransportConfig returns default UDP transport configuration
func DefaultUDPTransportConfig() *UDPTransportConfig {
	return &UDPTransportConfig{
		LocalAddr:       ":0",
		MaxPacketSize:   4096,
		ReceiveBuffer:   64 * 1024,
		SendBuffer:      64 * 1024,
		EnableMulticast: false,
		MulticastGroup:  "",
	}
}

// DefaultTCPTransportConfig returns default TCP transport configuration
func DefaultTCPTransportConfig() *TCPTransportConfig {
	return &TCPTransportConfig{
		KeepAlive:       true,
		KeepAlivePeriod: 30 * time.Second,
		NoDelay:         true,
		MaxIdleTime:     5 * time.Minute,
		ConnectTimeout:  30 * time.Second,
		ReadBuffer:      32 * 1024,
		WriteBuffer:     32 * 1024,
	}
}

// DefaultEnhancedTLSConfig returns default enhanced TLS configuration
func DefaultEnhancedTLSConfig() *EnhancedTLSConfig {
	return &EnhancedTLSConfig{
		MinVersion:             0x0303, // TLS 1.2
		MaxVersion:             0x0304, // TLS 1.3
		PreferServerCiphers:    false,
		InsecureSkipVerify:     false,
		ClientAuth:             "none",
		SessionTicketsDisabled: false,
		SessionCacheSize:       128,
		EnableOCSP:             false,
		OCSPStapling:           false,
		CertificateLifetime:    24 * time.Hour,
	}
}

// initializeConnectionPools initializes connection pools for all transports
func (tm *TransportManager) initializeConnectionPools(config *ConnectionPoolConfig) *ConnectionPools {
	if config == nil {
		config = DefaultConnectionPoolConfig()
	}

	return &ConnectionPools{
		UDP:    NewUDPConnectionPool(config.UDPMaxIdle, config.UDPMaxLifetime, tm.logger),
		TCP:    NewTCPConnectionPool(config.TCPMaxIdle, config.TCPMaxLifetime, tm.logger),
		logger: tm.logger,
	}
}

// RegisterTransport registers a transport client with the manager
func (tm *TransportManager) RegisterTransport(transportType TransportType, client TransportClient) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if client == nil {
		return fmt.Errorf("transport client cannot be nil")
	}

	tm.transports[transportType] = client
	tm.logger.Infof("Registered transport: %s", transportType)

	return nil
}

// UnregisterTransport removes a transport client from the manager
func (tm *TransportManager) UnregisterTransport(transportType TransportType) error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	if client, exists := tm.transports[transportType]; exists {
		client.Close()
		delete(tm.transports, transportType)
		tm.logger.Infof("Unregistered transport: %s", transportType)
	}

	return nil
}

// GetTransport returns a transport client by type
func (tm *TransportManager) GetTransport(transportType TransportType) (TransportClient, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	client, exists := tm.transports[transportType]
	if !exists {
		return nil, fmt.Errorf("transport type %s not registered", transportType)
	}

	return client, nil
}

// SelectTransport selects the best transport based on the configuration and current conditions
func (tm *TransportManager) SelectTransport(ctx context.Context) (TransportClient, TransportType, error) {
	tm.mu.RLock()
	defer tm.mu.RUnlock()

	switch tm.config.LoadBalancing {
	case LoadBalancingFailover:
		return tm.selectFailoverTransport(ctx)
	case LoadBalancingRoundRobin:
		return tm.selectRoundRobinTransport(ctx)
	case LoadBalancingWeighted:
		return tm.selectWeightedTransport(ctx)
	case LoadBalancingLeastLatency:
		return tm.selectLeastLatencyTransport(ctx)
	default:
		return tm.selectFailoverTransport(ctx)
	}
}

// selectFailoverTransport selects transport based on priority and availability
func (tm *TransportManager) selectFailoverTransport(_ context.Context) (TransportClient, TransportType, error) {
	// Sort transports by priority (highest first)
	prioritizedTransports := make([]TransportType, 0, len(tm.transports))
	for transportType := range tm.transports {
		prioritizedTransports = append(prioritizedTransports, transportType)
	}

	// Sort by priority
	for i := 0; i < len(prioritizedTransports)-1; i++ {
		for j := i + 1; j < len(prioritizedTransports); j++ {
			if tm.config.TransportPriorities[prioritizedTransports[i]] < tm.config.TransportPriorities[prioritizedTransports[j]] {
				prioritizedTransports[i], prioritizedTransports[j] = prioritizedTransports[j], prioritizedTransports[i]
			}
		}
	}

	// Try each transport in priority order
	for _, transportType := range prioritizedTransports {
		client := tm.transports[transportType]
		if client != nil && client.IsConnected() {
			return client, transportType, nil
		}
	}

	// If no connected transport found, return the highest priority one
	if len(prioritizedTransports) > 0 {
		transportType := prioritizedTransports[0]
		client := tm.transports[transportType]
		if client != nil {
			return client, transportType, nil
		}
	}

	return nil, "", fmt.Errorf("no transports available")
}

// selectRoundRobinTransport selects transport using round-robin algorithm
func (tm *TransportManager) selectRoundRobinTransport(ctx context.Context) (TransportClient, TransportType, error) {
	// For now, fallback to failover selection
	// TODO: Implement proper round-robin with state tracking
	return tm.selectFailoverTransport(ctx)
}

// selectWeightedTransport selects transport using weighted algorithm
func (tm *TransportManager) selectWeightedTransport(ctx context.Context) (TransportClient, TransportType, error) {
	// For now, fallback to failover selection
	// TODO: Implement proper weighted selection
	return tm.selectFailoverTransport(ctx)
}

// selectLeastLatencyTransport selects transport with the lowest latency
func (tm *TransportManager) selectLeastLatencyTransport(ctx context.Context) (TransportClient, TransportType, error) {
	var bestClient TransportClient
	var bestTransport TransportType
	var bestLatency time.Duration

	for transportType, client := range tm.transports {
		if client == nil || !client.IsConnected() {
			continue
		}

		stats := client.GetStatistics()
		if stats != nil && (bestClient == nil || stats.AverageRTT < bestLatency) {
			bestClient = client
			bestTransport = transportType
			bestLatency = stats.AverageRTT
		}
	}

	if bestClient != nil {
		return bestClient, bestTransport, nil
	}

	// Fallback to failover selection
	return tm.selectFailoverTransport(ctx)
}

// SendRequest sends a request using the best available transport
func (tm *TransportManager) SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
	client, transportType, err := tm.SelectTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to select transport: %w", err)
	}

	tm.logger.Debugf("Sending request using transport: %s", transportType)
	return client.SendRequest(ctx, req)
}

// GetConnectionPools returns the connection pools
func (tm *TransportManager) GetConnectionPools() *ConnectionPools {
	tm.mu.RLock()
	defer tm.mu.RUnlock()
	return tm.pools
}

// Close closes all transport clients and connection pools
func (tm *TransportManager) Close() error {
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Close all transport clients
	for transportType, client := range tm.transports {
		if client != nil {
			client.Close()
			tm.logger.Debugf("Closed transport: %s", transportType)
		}
	}

	// Close connection pools
	if tm.pools != nil {
		if tm.pools.UDP != nil {
			tm.pools.UDP.Close()
		}
		if tm.pools.TCP != nil {
			tm.pools.TCP.Close()
		}
	}

	return nil
}
