package client

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
)

func TestTCPClient(t *testing.T) {
	logger := log.NewDefaultLogger()

	t.Run("NewTCPClient", func(t *testing.T) {
		client, err := NewTCPClient(
			"127.0.0.1:1812",
			[]byte("secret"),
			30*time.Second,
			logger,
		)
		require.NoError(t, err)
		require.NotNil(t, client)

		assert.Equal(t, "127.0.0.1:1812", client.GetServerAddress())
		assert.Equal(t, 30*time.Second, client.GetTimeout())
		assert.False(t, client.IsConnected())
	})

	t.Run("NewTCPClient_ValidationErrors", func(t *testing.T) {
		// Empty server address
		_, err := NewTCPClient("", []byte("secret"), 30*time.Second, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "server address cannot be empty")

		// Empty shared secret
		_, err = NewTCPClient("127.0.0.1:1812", []byte{}, 30*time.Second, logger)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shared secret cannot be empty")
	})

	t.Run("SetTimeout", func(t *testing.T) {
		client, err := NewTCPClient(
			"127.0.0.1:1812",
			[]byte("secret"),
			30*time.Second,
			logger,
		)
		require.NoError(t, err)

		client.SetTimeout(10 * time.Second)
		assert.Equal(t, 10*time.Second, client.GetTimeout())
	})

	t.Run("GetStatistics", func(t *testing.T) {
		client, err := NewTCPClient(
			"127.0.0.1:1812",
			[]byte("secret"),
			30*time.Second,
			logger,
		)
		require.NoError(t, err)

		stats := client.GetStatistics()
		assert.NotNil(t, stats)
		assert.Equal(t, int64(0), stats.ConnectionsTotal)
		assert.Equal(t, int64(0), stats.RequestsSent)
		assert.Equal(t, int64(0), stats.ResponsesReceived)
	})

	t.Run("Connection_Failure", func(t *testing.T) {
		client, err := NewTCPClient(
			"127.0.0.1:19999", // Non-existent port
			[]byte("secret"),
			1*time.Second,
			logger,
		)
		require.NoError(t, err)

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()

		// Try to connect (should fail)
		err = client.Connect(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to connect")

		// Check statistics
		stats := client.GetStatistics()
		assert.True(t, stats.ConnectionsTotal > 0)
		assert.True(t, stats.ConnectionsFailures > 0)
	})

	t.Run("isConnectionError", func(t *testing.T) {
		// Test helper function
		assert.False(t, isConnectionError(nil))

		// Test with connection error strings
		assert.True(t, isConnectionError(fmt.Errorf("connection refused")))
		assert.True(t, isConnectionError(fmt.Errorf("connection reset")))
		assert.True(t, isConnectionError(fmt.Errorf("connection closed")))
		assert.False(t, isConnectionError(fmt.Errorf("some other error")))
	})

}

func TestTCPClient_PacketValidation(t *testing.T) {
	logger := log.NewDefaultLogger()

	client, err := NewTCPClient(
		"127.0.0.1:19999",
		[]byte("secret"),
		1*time.Second,
		logger,
	)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Test with nil packet
	_, err = client.SendRequest(ctx, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "request packet cannot be nil")
}
