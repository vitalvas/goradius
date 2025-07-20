package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.NotNil(t, config)
	assert.Len(t, config.Bindings, 2)
	assert.Equal(t, "0.0.0.0", config.Bindings[0].Address)
	assert.Equal(t, 1812, config.Bindings[0].Port)
	assert.Equal(t, 1813, config.Bindings[1].Port)
	assert.Equal(t, 30*time.Second, config.ReadTimeout)
	assert.Equal(t, 30*time.Second, config.WriteTimeout)
	assert.Equal(t, 4096, config.MaxRequestSize)
	assert.Equal(t, 10, config.Workers)
	assert.NotNil(t, config.Logger)
}

func TestNewServer(t *testing.T) {
	t.Run("with nil config", func(t *testing.T) {
		handler := NewDefaultHandler(log.NewDefaultLogger())
		server, err := NewServer(nil, handler)

		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.NotNil(t, server.config)
		assert.NotNil(t, server.handler)
		assert.NotNil(t, server.stats)
	})

	t.Run("with nil handler", func(t *testing.T) {
		config := DefaultConfig()
		server, err := NewServer(config, nil)

		assert.Error(t, err)
		assert.Nil(t, server)
		assert.Contains(t, err.Error(), "handler cannot be nil")
	})

	t.Run("with valid config and handler", func(t *testing.T) {
		config := DefaultConfig()
		handler := NewDefaultHandler(log.NewDefaultLogger())
		server, err := NewServer(config, handler)

		require.NoError(t, err)
		assert.NotNil(t, server)
		assert.Equal(t, config, server.config)
		assert.Equal(t, handler, server.handler)
	})
}

func TestServerStartStop(t *testing.T) {
	// Use different ports to avoid conflicts
	config := &Config{
		Bindings: []Binding{
			{
				Address:   "127.0.0.1",
				Port:      0, // Let system choose port
				IPVersion: 4,
				Transport: TransportUDP,
				Clients: []ClientConfig{
					{
						Networks: []string{"127.0.0.1"},
						Secret:   "testing123",
						Name:     "test-client",
					},
				},
			},
		},
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		MaxRequestSize: 4096,
		Workers:        2,
		Logger:         log.NewDefaultLogger(),
	}

	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	// Start server
	err = server.Start()
	require.NoError(t, err)

	// Verify server is running
	server.mu.RLock()
	listenerCount := len(server.udpListeners) + len(server.tcpListeners)
	server.mu.RUnlock()
	assert.Greater(t, listenerCount, 0)

	// Stop server
	err = server.Stop()
	assert.NoError(t, err)

	// Verify listeners are cleaned up
	time.Sleep(10 * time.Millisecond) // Give time for cleanup
}

func TestServerStatistics(t *testing.T) {
	server := &Server{
		stats: NewStatistics(),
	}

	stats := server.GetStatistics()
	assert.NotNil(t, stats)
	assert.Equal(t, uint64(0), stats.TotalRequests)
	assert.Equal(t, uint64(0), stats.TotalResponses)
}

func TestStatisticsUpdate(t *testing.T) {
	stats := NewStatistics()

	// Test updating request stats
	latency := 100 * time.Millisecond
	stats.UpdateRequestStats(latency, true)

	assert.Equal(t, uint64(1), stats.TotalRequests)
	assert.Equal(t, uint64(1), stats.TotalResponses)
	assert.Equal(t, latency, stats.MaxLatency)

	// Test failed request
	stats.UpdateRequestStats(latency, false)
	assert.Equal(t, uint64(2), stats.TotalRequests)
	assert.Equal(t, uint64(1), stats.TotalResponses) // Still 1
}

func TestListenerStatistics(t *testing.T) {
	stats := NewListenerStatistics()

	stats.UpdateRequestStats(100, 50, true)

	assert.Equal(t, uint64(100), stats.BytesReceived)
	assert.Equal(t, uint64(50), stats.BytesSent)
	assert.Equal(t, uint64(1), stats.Requests)
	assert.Equal(t, uint64(1), stats.Responses)
	assert.Equal(t, uint64(0), stats.Errors)
	assert.False(t, stats.LastRequest.IsZero())

	// Test error case
	stats.UpdateRequestStats(50, 0, false)
	assert.Equal(t, uint64(150), stats.BytesReceived)
	assert.Equal(t, uint64(2), stats.Requests)
	assert.Equal(t, uint64(1), stats.Responses) // Still 1
	assert.Equal(t, uint64(1), stats.Errors)
}

func TestServerConcurrency(t *testing.T) {
	// Test that server can handle concurrent operations safely
	config := &Config{
		Bindings: []Binding{
			{
				Address:   "127.0.0.1",
				Port:      0,
				IPVersion: 4,
				Transport: TransportUDP,
				Clients: []ClientConfig{
					{
						Networks: []string{"127.0.0.1"},
						Secret:   "testing123",
					},
				},
			},
		},
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		MaxRequestSize: 4096,
		Workers:        5,
		Logger:         log.NewDefaultLogger(),
	}

	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	// Test concurrent access to statistics
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			stats := server.GetStatistics()
			stats.UpdateRequestStats(time.Millisecond, true)
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := server.GetStatistics()
	assert.Equal(t, uint64(10), stats.TotalRequests)
}

func TestCreateListener(t *testing.T) {
	config := DefaultConfig()
	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	binding := Binding{
		Address:   "127.0.0.1",
		Port:      0, // Let system choose
		IPVersion: 4,
		Transport: TransportUDP,
		Clients: []ClientConfig{
			{
				Networks: []string{"127.0.0.1"},
				Secret:   "testing123",
			},
		},
	}

	err = server.createListener(binding, "test-key", 0)
	require.NoError(t, err)

	// Verify listener was created
	server.mu.RLock()
	listenerCount := len(server.udpListeners) + len(server.tcpListeners)
	server.mu.RUnlock()
	assert.Equal(t, 1, listenerCount)

	// Clean up
	server.Stop()
}

func TestIPVersionHandling(t *testing.T) {
	testCases := []struct {
		name      string
		ipVersion int
		address   string
		expected  string
	}{
		{"IPv4", 4, "127.0.0.1", "udp4"},
		{"IPv6", 6, "::1", "udp6"},
		{"Dual-stack", 0, "127.0.0.1", "udp"},
		{"Default", -1, "127.0.0.1", "udp"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultConfig()
			handler := NewDefaultHandler(config.Logger)
			server, err := NewServer(config, handler)
			require.NoError(t, err)

			binding := Binding{
				Address:   tc.address,
				Port:      0,
				IPVersion: tc.ipVersion,
				Transport: TransportUDP,
			}

			err = server.createListener(binding, "test-key", 0)
			require.NoError(t, err)

			// Verify listener was created
			server.mu.RLock()
			listenerCount := len(server.udpListeners) + len(server.tcpListeners)
			server.mu.RUnlock()
			assert.Equal(t, 1, listenerCount)

			server.Stop()
		})
	}
}

func TestServerLifecycle(t *testing.T) {
	config := &Config{
		Bindings: []Binding{
			{
				Address:   "127.0.0.1",
				Port:      0,
				IPVersion: 4,
				Transport: TransportUDP,
				Clients: []ClientConfig{
					{
						Networks: []string{"127.0.0.1"},
						Secret:   "testing123",
					},
				},
			},
		},
		ReadTimeout:    1 * time.Second,
		WriteTimeout:   1 * time.Second,
		MaxRequestSize: 4096,
		Workers:        2,
		Logger:         log.NewDefaultLogger(),
	}

	handler := NewDefaultHandler(config.Logger)
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	// Test multiple start/stop cycles
	for i := 0; i < 3; i++ {
		err = server.Start()
		require.NoError(t, err)

		// Verify server is running
		server.mu.RLock()
		listenerCount := len(server.udpListeners) + len(server.tcpListeners)
		server.mu.RUnlock()
		assert.Greater(t, listenerCount, 0)

		err = server.Stop()
		require.NoError(t, err)

		// Give time for cleanup
		time.Sleep(10 * time.Millisecond)
	}
}

// Benchmark server creation
func BenchmarkNewServer(b *testing.B) {
	config := DefaultConfig()
	handler := NewDefaultHandler(config.Logger)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		server, err := NewServer(config, handler)
		if err != nil {
			b.Fatal(err)
		}
		_ = server
	}
}

// Benchmark statistics updates
func BenchmarkStatisticsUpdate(b *testing.B) {
	stats := NewStatistics()
	latency := time.Millisecond

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		stats.UpdateRequestStats(latency, true)
	}
}
