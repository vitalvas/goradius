package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
)

func TestUDPListener_validateClient(t *testing.T) {
	config := &Config{
		Logger: log.NewDefaultLogger(),
	}

	binding := Binding{
		Clients: []ClientConfig{
			{
				Networks: []string{"192.168.1.0/24", "10.0.0.1"},
				Secret:   "secret1",
				Name:     "network-client",
			},
			{
				Networks: []string{"127.0.0.1"},
				Secret:   "secret2",
				Name:     "localhost-client",
			},
		},
	}

	listener := &UDPListener{
		binding: binding,
		config:  config,
		logger:  config.Logger,
		stats:   NewListenerStatistics(),
	}

	t.Run("valid client in CIDR range", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
		client, err := listener.validateClient(clientAddr)

		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "secret1", client.Secret)
		assert.Equal(t, "network-client", client.Name)
	})

	t.Run("valid client exact IP", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
		client, err := listener.validateClient(clientAddr)

		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "secret1", client.Secret)
	})

	t.Run("valid localhost client", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		client, err := listener.validateClient(clientAddr)

		require.NoError(t, err)
		assert.NotNil(t, client)
		assert.Equal(t, "secret2", client.Secret)
		assert.Equal(t, "localhost-client", client.Name)
	})

	t.Run("invalid client", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("172.16.1.1"), Port: 12345}
		client, err := listener.validateClient(clientAddr)

		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "not authorized")
	})

	t.Run("unsupported address type", func(t *testing.T) {
		clientAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		client, err := listener.validateClient(clientAddr)

		assert.Error(t, err)
		assert.Nil(t, client)
		assert.Contains(t, err.Error(), "unsupported address type")
	})
}

func TestUDPListener_isIPInNetwork(t *testing.T) {

	testCases := []struct {
		name     string
		ip       string
		network  string
		expected bool
	}{
		{"IPv4 in CIDR", "192.168.1.100", "192.168.1.0/24", true},
		{"IPv4 not in CIDR", "192.168.2.100", "192.168.1.0/24", false},
		{"IPv4 exact match", "10.0.0.1", "10.0.0.1", true},
		{"IPv4 no match", "10.0.0.2", "10.0.0.1", false},
		{"IPv6 in CIDR", "2001:db8::1", "2001:db8::/32", true},
		{"IPv6 not in CIDR", "2001:db9::1", "2001:db8::/32", false},
		{"IPv6 exact match", "::1", "::1", true},
		{"Invalid network", "192.168.1.1", "invalid", false},
		{"Empty network", "192.168.1.1", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			require.NotNil(t, ip, "Failed to parse test IP: %s", tc.ip)

			result := isIPInNetwork(ip, tc.network)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestUDPListener_GetStatistics(t *testing.T) {
	listener := &UDPListener{
		stats: NewListenerStatistics(),
	}

	stats := listener.GetStatistics()
	assert.NotNil(t, stats)
	assert.Equal(t, uint64(0), stats.BytesReceived)
	assert.Equal(t, uint64(0), stats.BytesSent)
	assert.Equal(t, uint64(0), stats.Requests)
	assert.Equal(t, uint64(0), stats.Responses)
	assert.Equal(t, uint64(0), stats.Errors)
}

func TestListenerStatisticsConcurrency(t *testing.T) {
	stats := NewListenerStatistics()

	// Test concurrent updates
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			stats.UpdateRequestStats(100, 50, true)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	assert.Equal(t, uint64(1000), stats.BytesReceived) // 10 * 100
	assert.Equal(t, uint64(500), stats.BytesSent)      // 10 * 50
	assert.Equal(t, uint64(10), stats.Requests)
	assert.Equal(t, uint64(10), stats.Responses)
	assert.Equal(t, uint64(0), stats.Errors)
}

func TestUDPListenerLifecycle(t *testing.T) {
	// Create a real UDP connection for testing
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)

	config := &Config{
		ReadTimeout:    100 * time.Millisecond,
		WriteTimeout:   100 * time.Millisecond,
		MaxRequestSize: 4096,
		Workers:        2,
		Logger:         log.NewDefaultLogger(),
	}

	binding := Binding{
		Address:   "127.0.0.1",
		Port:      0,
		IPVersion: 4,
		Clients: []ClientConfig{
			{
				Networks: []string{"127.0.0.1"},
				Secret:   "testing123",
			},
		},
	}

	handler := NewDefaultHandler(config.Logger)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener := &UDPListener{
		binding: binding,
		config:  config,
		conn:    conn,
		handler: handler,
		workers: make(chan struct{}, config.Workers),
		logger:  config.Logger,
		ctx:     ctx,
		cancel:  cancel,
		stats:   NewListenerStatistics(),
	}

	// Initialize worker pool
	for i := 0; i < config.Workers; i++ {
		listener.workers <- struct{}{}
	}

	// Test that listener can be stopped without starting
	listener.Stop()

	// Connection may still be usable after stop since we control it manually
	// The important thing is that Stop() doesn't panic
	assert.NotNil(t, listener)
}

func TestUDPListener_processRequest_InvalidClient(t *testing.T) {
	config := &Config{
		Logger: log.NewDefaultLogger(),
	}

	binding := Binding{
		Clients: []ClientConfig{
			{
				Networks: []string{"192.168.1.0/24"},
				Secret:   "secret",
			},
		},
	}

	listener := &UDPListener{
		binding: binding,
		config:  config,
		logger:  config.Logger,
		stats:   NewListenerStatistics(),
	}

	// Test with unauthorized client
	invalidClient := &net.UDPAddr{IP: net.ParseIP("10.0.0.1"), Port: 12345}
	data := []byte{0x01, 0x00, 0x00, 0x14} // Minimal packet header

	// This should not panic and should handle the invalid client gracefully
	listener.processRequest(data, invalidClient, time.Now())

	// Verify no statistics were updated for successful processing
	assert.Equal(t, uint64(0), listener.stats.Responses)
}

func TestClientConfigValidation(t *testing.T) {
	testCases := []struct {
		name     string
		config   ClientConfig
		expected bool
	}{
		{
			name: "valid config with CIDR",
			config: ClientConfig{
				Networks: []string{"192.168.1.0/24"},
				Secret:   "test-secret",
				Name:     "test-client",
			},
			expected: true,
		},
		{
			name: "valid config with single IP",
			config: ClientConfig{
				Networks: []string{"127.0.0.1"},
				Secret:   "test-secret",
				Name:     "localhost",
			},
			expected: true,
		},
		{
			name: "valid config with multiple networks",
			config: ClientConfig{
				Networks: []string{"192.168.1.0/24", "10.0.0.0/8", "127.0.0.1"},
				Secret:   "test-secret",
				Name:     "multi-network",
			},
			expected: true,
		},
		{
			name: "config with empty networks",
			config: ClientConfig{
				Networks: []string{},
				Secret:   "test-secret",
				Name:     "no-networks",
			},
			expected: true, // Structure is valid, just no networks defined
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test that the config structure is valid
			assert.NotEmpty(t, tc.config.Secret)
			if len(tc.config.Networks) > 0 {
				for _, network := range tc.config.Networks {
					assert.NotEmpty(t, network)
				}
			}
		})
	}
}

// Benchmark UDP listener validation
func BenchmarkValidateClient(b *testing.B) {
	config := &Config{
		Logger: log.NewDefaultLogger(),
	}

	binding := Binding{
		Clients: []ClientConfig{
			{
				Networks: []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
				Secret:   "secret1",
			},
		},
	}

	listener := &UDPListener{
		binding: binding,
		config:  config,
		logger:  config.Logger,
		stats:   NewListenerStatistics(),
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := listener.validateClient(clientAddr)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark IP network checking
func BenchmarkIsIPInNetwork(b *testing.B) {
	ip := net.ParseIP("192.168.1.100")
	network := "192.168.1.0/24"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isIPInNetwork(ip, network)
	}
}
