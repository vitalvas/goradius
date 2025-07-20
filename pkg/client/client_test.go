package client

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	assert.Equal(t, TransportUDP, config.Transport)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 3, config.MaxRetries)
	assert.Equal(t, 1*time.Second, config.RetryInterval)
	assert.Equal(t, 5*time.Second, config.FailoverTimeout)
	assert.Equal(t, 30*time.Second, config.HealthCheckInterval)
	assert.NotNil(t, config.Logger)
}

func TestValidateConfig(t *testing.T) {
	tests := []struct {
		name        string
		config      *Config
		expectError bool
	}{
		{
			name: "valid config",
			config: &Config{
				Servers: []ServerConfig{
					{
						Address:      "localhost",
						Port:         1812,
						SharedSecret: []byte("secret"),
					},
				},
				Transport: TransportUDP,
				Timeout:   30 * time.Second,
			},
			expectError: false,
		},
		{
			name: "no servers",
			config: &Config{
				Transport: TransportUDP,
				Timeout:   30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "empty server address",
			config: &Config{
				Servers: []ServerConfig{
					{
						Address:      "",
						Port:         1812,
						SharedSecret: []byte("secret"),
					},
				},
				Transport: TransportUDP,
				Timeout:   30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "invalid port",
			config: &Config{
				Servers: []ServerConfig{
					{
						Address:      "localhost",
						Port:         0,
						SharedSecret: []byte("secret"),
					},
				},
				Transport: TransportUDP,
				Timeout:   30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "no shared secret",
			config: &Config{
				Servers: []ServerConfig{
					{
						Address: "localhost",
						Port:    1812,
					},
				},
				Transport: TransportUDP,
				Timeout:   30 * time.Second,
			},
			expectError: true,
		},
		{
			name: "global shared secret",
			config: &Config{
				Servers: []ServerConfig{
					{
						Address: "localhost",
						Port:    1812,
					},
				},
				Transport:    TransportUDP,
				Timeout:      30 * time.Second,
				SharedSecret: []byte("global-secret"),
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateConfig(tt.config)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "localhost",
				Port:         1812,
				SharedSecret: []byte("secret"),
			},
		},
		Transport: TransportUDP,
		Timeout:   30 * time.Second,
		Logger:    log.NewDefaultLogger(),
	}

	client, err := NewClient(config)
	require.NoError(t, err)
	require.NotNil(t, client)

	radiusClient, ok := client.(*RADIUSClient)
	require.True(t, ok)

	assert.Equal(t, config, radiusClient.config)
	assert.Len(t, radiusClient.servers, 1)
	assert.Len(t, radiusClient.serverStates, 1)
	assert.NotNil(t, radiusClient.stats)
	assert.NotNil(t, radiusClient.healthChecker)

	// Test cleanup
	err = client.Close()
	assert.NoError(t, err)
}

func TestNewClientWithNilConfig(t *testing.T) {
	client, err := NewClient(nil)
	require.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "at least one server must be configured")
}

func TestNewStatistics(t *testing.T) {
	stats := NewStatistics()

	assert.NotNil(t, stats)
	assert.Equal(t, int64(0), stats.RequestsSent)
	assert.Equal(t, int64(0), stats.ResponsesReceived)
	assert.Equal(t, int64(0), stats.Timeouts)
	assert.Equal(t, int64(0), stats.Errors)
	assert.Equal(t, int64(0), stats.Retries)
	assert.Equal(t, int64(0), stats.FailoverCount)
	assert.Equal(t, time.Duration(0), stats.AverageRTT)
	assert.Equal(t, time.Duration(0), stats.MinRTT)
	assert.Equal(t, time.Duration(0), stats.MaxRTT)
	assert.NotNil(t, stats.ServerStatistics)
	assert.Equal(t, 0, len(stats.ServerStatistics))
}

func TestRADIUSClientGenerateRequestID(t *testing.T) {
	client := &RADIUSClient{}

	// Test that IDs are incremented
	id1 := client.generateRequestID()
	id2 := client.generateRequestID()
	id3 := client.generateRequestID()

	assert.Equal(t, uint8(1), id1)
	assert.Equal(t, uint8(2), id2)
	assert.Equal(t, uint8(3), id3)
}

func TestRADIUSClientPrepareRequest(t *testing.T) {
	client := &RADIUSClient{}
	req := packet.New(packet.CodeAccessRequest, 0)

	// Add some attributes
	req.AddAttribute(packet.NewStringAttribute(packet.AttrUserName, "testuser"))
	req.AddAttribute(packet.NewStringAttribute(packet.AttrUserPassword, "testpass"))

	err := client.prepareRequest(req)
	require.NoError(t, err)

	// Check that identifier was set
	assert.NotEqual(t, uint8(0), req.Identifier)

	// Check that authenticator was set
	assert.NotEqual(t, [16]byte{}, req.Authenticator)

	// Check that length was calculated
	expectedLength := uint16(packet.PacketHeaderLength)
	for _, attr := range req.Attributes {
		expectedLength += uint16(attr.Length)
	}
	assert.Equal(t, expectedLength, req.Length)
}

func TestServerError(t *testing.T) {
	tests := []struct {
		name        string
		err         error
		expectError bool
	}{
		{
			name:        "nil error",
			err:         nil,
			expectError: false,
		},
		{
			name:        "connection refused",
			err:         fmt.Errorf("connection refused"),
			expectError: true,
		},
		{
			name:        "connection reset",
			err:         fmt.Errorf("connection reset"),
			expectError: true,
		},
		{
			name:        "no route to host",
			err:         fmt.Errorf("no route to host"),
			expectError: true,
		},
		{
			name:        "network unreachable",
			err:         fmt.Errorf("network unreachable"),
			expectError: true,
		},
		{
			name:        "generic error",
			err:         fmt.Errorf("generic error"),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isServerError(tt.err)
			assert.Equal(t, tt.expectError, result)
		})
	}
}

func TestRADIUSClientMarkServerUnhealthy(t *testing.T) {
	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "localhost",
				Port:         1812,
				SharedSecret: []byte("secret"),
			},
		},
		Transport: TransportUDP,
		Logger:    log.NewDefaultLogger(),
	}

	client, err := NewClient(config)
	require.NoError(t, err)
	defer client.Close()

	radiusClient, ok := client.(*RADIUSClient)
	require.True(t, ok)

	serverAddr := "localhost:1812"

	// Initially healthy
	state := radiusClient.serverStates[serverAddr]
	assert.True(t, state.healthy)
	assert.Equal(t, int64(0), state.failureCount)

	// Mark as unhealthy
	radiusClient.markServerUnhealthy(serverAddr)

	// Check state
	assert.False(t, state.healthy)
	assert.Equal(t, int64(1), state.failureCount)
}

func TestRADIUSClientUpdateStatistics(t *testing.T) {
	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "localhost",
				Port:         1812,
				SharedSecret: []byte("secret"),
			},
		},
		Transport: TransportUDP,
		Logger:    log.NewDefaultLogger(),
	}

	client, err := NewClient(config)
	require.NoError(t, err)
	defer client.Close()

	radiusClient, ok := client.(*RADIUSClient)
	require.True(t, ok)

	serverAddr := "localhost:1812"
	rtt := 100 * time.Millisecond

	// Update statistics
	radiusClient.updateStatistics(serverAddr, rtt, true)

	// Check global statistics
	assert.Equal(t, rtt, radiusClient.stats.MinRTT)
	assert.Equal(t, rtt, radiusClient.stats.MaxRTT)
	assert.Equal(t, rtt, radiusClient.stats.AverageRTT)

	// Check server statistics
	require.NotNil(t, radiusClient.stats.ServerStatistics)
	serverStats, exists := radiusClient.stats.ServerStatistics[serverAddr]
	require.True(t, exists)
	assert.Equal(t, serverAddr, serverStats.Address)
	assert.Equal(t, int64(1), serverStats.RequestsSent)
	assert.Equal(t, int64(1), serverStats.ResponsesReceived)
	assert.Equal(t, int64(0), serverStats.Errors)

	// Update with failure
	radiusClient.updateStatistics(serverAddr, rtt, false)

	// Check updated statistics
	assert.Equal(t, int64(2), serverStats.RequestsSent)
	assert.Equal(t, int64(1), serverStats.ResponsesReceived)
	assert.Equal(t, int64(1), serverStats.Errors)
}

func TestRADIUSClientGetStatistics(t *testing.T) {
	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "localhost",
				Port:         1812,
				SharedSecret: []byte("secret"),
			},
		},
		Transport: TransportUDP,
		Logger:    log.NewDefaultLogger(),
	}

	client, err := NewClient(config)
	require.NoError(t, err)
	defer client.Close()

	stats := client.GetStatistics()
	require.NotNil(t, stats)

	assert.Equal(t, int64(0), stats.RequestsSent)
	assert.Equal(t, int64(0), stats.ResponsesReceived)
	assert.Equal(t, int64(0), stats.Timeouts)
	assert.Equal(t, int64(0), stats.Errors)
	assert.Equal(t, int64(0), stats.Retries)
	assert.Equal(t, int64(0), stats.FailoverCount)
	assert.NotNil(t, stats.ServerStatistics)
}

func TestRADIUSClientCopyServerStatistics(t *testing.T) {
	config := &Config{
		Servers: []ServerConfig{
			{
				Address:      "localhost",
				Port:         1812,
				SharedSecret: []byte("secret"),
			},
		},
		Transport: TransportUDP,
		Logger:    log.NewDefaultLogger(),
	}

	client, err := NewClient(config)
	require.NoError(t, err)
	defer client.Close()

	radiusClient, ok := client.(*RADIUSClient)
	require.True(t, ok)

	// Add some server statistics
	serverAddr := "localhost:1812"
	radiusClient.stats.ServerStatistics = map[string]*ServerStatistics{
		serverAddr: {
			Address:           serverAddr,
			Active:            true,
			Healthy:           true,
			RequestsSent:      10,
			ResponsesReceived: 9,
			Timeouts:          0,
			Errors:            1,
			AverageRTT:        50 * time.Millisecond,
			FailureCount:      1,
			RecoveryCount:     0,
		},
	}

	// Copy statistics
	copied := radiusClient.copyServerStatistics()

	// Check that copy is independent
	require.NotNil(t, copied)
	require.Len(t, copied, 1)

	copiedStats, exists := copied[serverAddr]
	require.True(t, exists)

	assert.Equal(t, serverAddr, copiedStats.Address)
	assert.True(t, copiedStats.Active)
	assert.True(t, copiedStats.Healthy)
	assert.Equal(t, int64(10), copiedStats.RequestsSent)
	assert.Equal(t, int64(9), copiedStats.ResponsesReceived)
	assert.Equal(t, int64(0), copiedStats.Timeouts)
	assert.Equal(t, int64(1), copiedStats.Errors)
	assert.Equal(t, 50*time.Millisecond, copiedStats.AverageRTT)
	assert.Equal(t, int64(1), copiedStats.FailureCount)
	assert.Equal(t, int64(0), copiedStats.RecoveryCount)

	// Modify original and ensure copy is not affected
	radiusClient.stats.ServerStatistics[serverAddr].RequestsSent = 20
	assert.Equal(t, int64(10), copiedStats.RequestsSent)
}

func TestTransportTypes(t *testing.T) {
	assert.Equal(t, TransportType("udp"), TransportUDP)
	assert.Equal(t, TransportType("tcp"), TransportTCP)
	// RADSEC is now handled as TCP with TLS
}

func TestServerConfig(t *testing.T) {
	config := ServerConfig{
		Address:      "localhost",
		Port:         1812,
		SharedSecret: []byte("secret"),
		Priority:     1,
		Weight:       100,
		Timeout:      30 * time.Second,
	}

	assert.Equal(t, "localhost", config.Address)
	assert.Equal(t, 1812, config.Port)
	assert.Equal(t, []byte("secret"), config.SharedSecret)
	assert.Equal(t, 1, config.Priority)
	assert.Equal(t, 100, config.Weight)
	assert.Equal(t, 30*time.Second, config.Timeout)
}

func TestStatistics(t *testing.T) {
	stats := &Statistics{
		RequestsSent:        100,
		ResponsesReceived:   95,
		Timeouts:            2,
		Errors:              3,
		Retries:             5,
		FailoverCount:       1,
		ActiveServer:        "localhost:1812",
		AverageRTT:          50 * time.Millisecond,
		MinRTT:              10 * time.Millisecond,
		MaxRTT:              100 * time.Millisecond,
		ConnectionsActive:   2,
		ConnectionsTotal:    10,
		ConnectionsFailures: 1,
		BytesSent:           10000,
		BytesReceived:       9500,
		LastRequest:         time.Now(),
		LastResponse:        time.Now(),
		StartTime:           time.Now().Add(-1 * time.Hour),
		ServerStatistics:    make(map[string]*ServerStatistics),
	}

	assert.Equal(t, int64(100), stats.RequestsSent)
	assert.Equal(t, int64(95), stats.ResponsesReceived)
	assert.Equal(t, int64(2), stats.Timeouts)
	assert.Equal(t, int64(3), stats.Errors)
	assert.Equal(t, int64(5), stats.Retries)
	assert.Equal(t, int64(1), stats.FailoverCount)
	assert.Equal(t, "localhost:1812", stats.ActiveServer)
	assert.Equal(t, 50*time.Millisecond, stats.AverageRTT)
	assert.Equal(t, 10*time.Millisecond, stats.MinRTT)
	assert.Equal(t, 100*time.Millisecond, stats.MaxRTT)
	assert.Equal(t, int64(2), stats.ConnectionsActive)
	assert.Equal(t, int64(10), stats.ConnectionsTotal)
	assert.Equal(t, int64(1), stats.ConnectionsFailures)
	assert.Equal(t, int64(10000), stats.BytesSent)
	assert.Equal(t, int64(9500), stats.BytesReceived)
	assert.NotNil(t, stats.ServerStatistics)
}
