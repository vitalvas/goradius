package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// MockTransportClient implements TransportClient for testing
type MockTransportClient struct {
	serverAddr  string
	timeout     time.Duration
	connected   bool
	stats       *Statistics
	sendReqFunc func(ctx context.Context, req *packet.Packet) (*packet.Packet, error)
}

func NewMockTransportClient(serverAddr string, connected bool) *MockTransportClient {
	return &MockTransportClient{
		serverAddr: serverAddr,
		timeout:    30 * time.Second,
		connected:  connected,
		stats: &Statistics{
			AverageRTT: 10 * time.Millisecond,
		},
	}
}

func (m *MockTransportClient) SendRequest(ctx context.Context, req *packet.Packet) (*packet.Packet, error) {
	if m.sendReqFunc != nil {
		return m.sendReqFunc(ctx, req)
	}
	// Return a mock response
	resp := packet.New(packet.CodeAccessAccept, req.Identifier)
	return resp, nil
}

func (m *MockTransportClient) GetStatistics() *Statistics {
	return m.stats
}

func (m *MockTransportClient) Close() error {
	return nil
}

func (m *MockTransportClient) IsConnected() bool {
	return m.connected
}

func (m *MockTransportClient) GetServerAddress() string {
	return m.serverAddr
}

func (m *MockTransportClient) SetTimeout(timeout time.Duration) {
	m.timeout = timeout
}

func (m *MockTransportClient) GetTimeout() time.Duration {
	return m.timeout
}

func TestDefaultTransportConfig(t *testing.T) {
	config := DefaultTransportConfig()

	assert.Equal(t, TransportUDP, config.DefaultTransport)
	assert.True(t, config.EnableFailover)
	assert.True(t, config.EnablePooling)
	assert.Equal(t, LoadBalancingFailover, config.LoadBalancing)
	assert.NotNil(t, config.PoolConfig)
	assert.NotNil(t, config.UDPConfig)
	assert.NotNil(t, config.TCPConfig)
	// RADSEC functionality is now part of TCP with TLS

	// Check transport priorities
	assert.Equal(t, 1, config.TransportPriorities[TransportUDP])
	assert.Equal(t, 2, config.TransportPriorities[TransportTCP])
	// RADSEC is now handled as TCP with TLS
}

func TestDefaultConnectionPoolConfig(t *testing.T) {
	config := DefaultConnectionPoolConfig()

	assert.Equal(t, 10, config.UDPMaxIdle)
	assert.Equal(t, 5, config.TCPMaxIdle)
	// RADSEC functionality is now part of TCP with TLS
	assert.Equal(t, 30*time.Minute, config.UDPMaxLifetime)
	assert.Equal(t, 10*time.Minute, config.TCPMaxLifetime)
	// RADSEC functionality is now part of TCP with TLS
	assert.True(t, config.EnableMetrics)
}

func TestDefaultUDPTransportConfig(t *testing.T) {
	config := DefaultUDPTransportConfig()

	assert.Equal(t, ":0", config.LocalAddr)
	assert.Equal(t, 4096, config.MaxPacketSize)
	assert.Equal(t, 64*1024, config.ReceiveBuffer)
	assert.Equal(t, 64*1024, config.SendBuffer)
	assert.False(t, config.EnableMulticast)
}

func TestDefaultTCPTransportConfig(t *testing.T) {
	config := DefaultTCPTransportConfig()

	assert.True(t, config.KeepAlive)
	assert.Equal(t, 30*time.Second, config.KeepAlivePeriod)
	assert.True(t, config.NoDelay)
	assert.Equal(t, 5*time.Minute, config.MaxIdleTime)
	assert.Equal(t, 30*time.Second, config.ConnectTimeout)
}

// TestDefaultRADSECTransportConfig - RADSEC functionality is now part of TCP with TLS

func TestDefaultEnhancedTLSConfig(t *testing.T) {
	config := DefaultEnhancedTLSConfig()

	assert.Equal(t, uint16(0x0303), config.MinVersion) // TLS 1.2
	assert.Equal(t, uint16(0x0304), config.MaxVersion) // TLS 1.3
	assert.False(t, config.PreferServerCiphers)
	assert.False(t, config.InsecureSkipVerify)
	assert.Equal(t, "none", config.ClientAuth)
	assert.Equal(t, 128, config.SessionCacheSize)
	assert.Equal(t, 24*time.Hour, config.CertificateLifetime)
}

func TestNewTransportManager(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()

	tm := NewTransportManager(config, logger)

	assert.NotNil(t, tm)
	assert.NotNil(t, tm.config)
	assert.NotNil(t, tm.logger)
	assert.NotNil(t, tm.transports)
	assert.NotNil(t, tm.pools)
	assert.NotNil(t, tm.pools.UDP)
	assert.NotNil(t, tm.pools.TCP)
	// RADSEC functionality is now part of TCP with TLS

	// Clean up
	tm.Close()
}

func TestNewTransportManagerWithNilConfig(t *testing.T) {
	logger := log.NewDefaultLogger()

	tm := NewTransportManager(nil, logger)

	assert.NotNil(t, tm)
	assert.NotNil(t, tm.config)
	assert.Equal(t, TransportUDP, tm.config.DefaultTransport)

	// Clean up
	tm.Close()
}

func TestTransportManagerRegisterTransport(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Create mock client
	mockClient := NewMockTransportClient("localhost:1812", true)

	// Register transport
	err := tm.RegisterTransport(TransportUDP, mockClient)
	assert.NoError(t, err)

	// Verify registration
	client, err := tm.GetTransport(TransportUDP)
	assert.NoError(t, err)
	assert.Equal(t, mockClient, client)
}

func TestTransportManagerRegisterNilTransport(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Try to register nil transport
	err := tm.RegisterTransport(TransportUDP, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport client cannot be nil")
}

func TestTransportManagerUnregisterTransport(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Create and register mock client
	mockClient := NewMockTransportClient("localhost:1812", true)
	err := tm.RegisterTransport(TransportUDP, mockClient)
	require.NoError(t, err)

	// Unregister transport
	err = tm.UnregisterTransport(TransportUDP)
	assert.NoError(t, err)

	// Verify unregistration
	_, err = tm.GetTransport(TransportUDP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport type udp not registered")
}

func TestTransportManagerGetTransportNotRegistered(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Try to get unregistered transport
	_, err := tm.GetTransport(TransportUDP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "transport type udp not registered")
}

func TestTransportManagerSelectFailoverTransport(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	config.LoadBalancing = LoadBalancingFailover
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Register transports with different priorities
	udpClient := NewMockTransportClient("localhost:1812", false) // Not connected
	tcpClient := NewMockTransportClient("localhost:1812", true)  // Connected
	// RADSEC functionality is now part of TCP with TLS // Connected

	tm.RegisterTransport(TransportUDP, udpClient)
	tm.RegisterTransport(TransportTCP, tcpClient)
	// RADSEC is now handled as TCP with TLS

	// Select transport - should choose TCP (highest priority and connected)
	client, _, err := tm.SelectTransport(context.Background())
	assert.NoError(t, err)
	// RADSEC is now handled as TCP with TLS
	assert.Equal(t, tcpClient, client)
}

func TestTransportManagerSelectLeastLatencyTransport(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	config.LoadBalancing = LoadBalancingLeastLatency
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Register transports with different latencies
	udpClient := NewMockTransportClient("localhost:1812", true)
	udpClient.stats.AverageRTT = 5 * time.Millisecond // Lowest latency

	tcpClient := NewMockTransportClient("localhost:1812", true)
	tcpClient.stats.AverageRTT = 10 * time.Millisecond

	// RADSEC functionality is now part of TCP with TLS

	tm.RegisterTransport(TransportUDP, udpClient)
	tm.RegisterTransport(TransportTCP, tcpClient)
	// RADSEC is now handled as TCP with TLS

	// Select transport - should choose UDP (lowest latency)
	client, transportType, err := tm.SelectTransport(context.Background())
	assert.NoError(t, err)
	assert.Equal(t, TransportUDP, transportType)
	assert.Equal(t, udpClient, client)
}

func TestTransportManagerSelectTransportNoTransports(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Try to select transport when none are registered
	_, _, err := tm.SelectTransport(context.Background())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no transports available")
}

func TestTransportManagerSendRequest(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Create mock client with custom send function
	mockClient := NewMockTransportClient("localhost:1812", true)
	mockClient.sendReqFunc = func(_ context.Context, req *packet.Packet) (*packet.Packet, error) {
		resp := packet.New(packet.CodeAccessAccept, req.Identifier)
		return resp, nil
	}

	tm.RegisterTransport(TransportUDP, mockClient)

	// Create test request
	req := packet.New(packet.CodeAccessRequest, 1)

	// Send request
	resp, err := tm.SendRequest(context.Background(), req)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, packet.CodeAccessAccept, resp.Code)
	assert.Equal(t, req.Identifier, resp.Identifier)
}

func TestTransportManagerClose(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)

	// Register some transports
	udpClient := NewMockTransportClient("localhost:1812", true)
	tcpClient := NewMockTransportClient("localhost:1812", true)

	tm.RegisterTransport(TransportUDP, udpClient)
	tm.RegisterTransport(TransportTCP, tcpClient)

	// Close transport manager
	err := tm.Close()
	assert.NoError(t, err)
}

func TestConnectionPoolsInitialization(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	pools := tm.GetConnectionPools()
	assert.NotNil(t, pools)
	assert.NotNil(t, pools.UDP)
	assert.NotNil(t, pools.TCP)
	// RADSEC functionality is now part of TCP with TLS
}

func TestTransportManagerWithPoolingDisabled(t *testing.T) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	config.EnablePooling = false

	tm := NewTransportManager(config, logger)
	defer tm.Close()

	pools := tm.GetConnectionPools()
	assert.Nil(t, pools)
}

func TestLoadBalancingStrategies(t *testing.T) {
	strategies := []LoadBalancingStrategy{
		LoadBalancingRoundRobin,
		LoadBalancingWeighted,
		LoadBalancingLeastLatency,
		LoadBalancingFailover,
	}

	for _, strategy := range strategies {
		t.Run(string(strategy), func(t *testing.T) {
			logger := log.NewDefaultLogger()
			config := DefaultTransportConfig()
			config.LoadBalancing = strategy
			tm := NewTransportManager(config, logger)
			defer tm.Close()

			// Register a transport
			mockClient := NewMockTransportClient("localhost:1812", true)
			tm.RegisterTransport(TransportUDP, mockClient)

			// Select transport
			client, transportType, err := tm.SelectTransport(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, TransportUDP, transportType)
			assert.Equal(t, mockClient, client)
		})
	}
}

// Benchmark tests
func BenchmarkTransportManagerSelectTransport(b *testing.B) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Register transports
	udpClient := NewMockTransportClient("localhost:1812", true)
	tcpClient := NewMockTransportClient("localhost:1812", true)
	// RADSEC functionality is now part of TCP with TLS

	tm.RegisterTransport(TransportUDP, udpClient)
	tm.RegisterTransport(TransportTCP, tcpClient)
	// RADSEC is now handled as TCP with TLS

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := tm.SelectTransport(context.Background())
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTransportManagerSendRequest(b *testing.B) {
	logger := log.NewDefaultLogger()
	config := DefaultTransportConfig()
	tm := NewTransportManager(config, logger)
	defer tm.Close()

	// Create mock client
	mockClient := NewMockTransportClient("localhost:1812", true)
	mockClient.sendReqFunc = func(_ context.Context, req *packet.Packet) (*packet.Packet, error) {
		resp := packet.New(packet.CodeAccessAccept, req.Identifier)
		return resp, nil
	}

	tm.RegisterTransport(TransportUDP, mockClient)

	// Create test request
	req := packet.New(packet.CodeAccessRequest, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := tm.SendRequest(context.Background(), req)
		if err != nil {
			b.Fatal(err)
		}
	}
}
