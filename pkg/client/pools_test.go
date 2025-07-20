package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestUDPConnectionPool(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(2, 1*time.Minute, logger)
	defer pool.Close()

	// Test getting a connection
	conn1, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn1)
	assert.Equal(t, ":0", conn1.localAddr)
	assert.True(t, conn1.inUse)

	// Test releasing connection
	pool.ReleaseConnection(conn1)
	assert.False(t, conn1.inUse)

	// Test getting the same connection again
	conn2, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.Equal(t, conn1, conn2) // Should be the same connection
	assert.True(t, conn2.inUse)

	pool.ReleaseConnection(conn2)
}

func TestUDPConnectionPoolMultipleAddresses(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(2, 1*time.Minute, logger)
	defer pool.Close()

	// Get connections for different addresses
	conn1, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn1)

	conn2, err := pool.GetConnection("127.0.0.1:0")
	assert.NoError(t, err)
	assert.NotNil(t, conn2)

	// Should be different connections
	assert.NotEqual(t, conn1, conn2)
	assert.NotEqual(t, conn1.conn, conn2.conn)

	pool.ReleaseConnection(conn1)
	pool.ReleaseConnection(conn2)
}

func TestUDPConnectionPoolExpiration(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(2, 100*time.Millisecond, logger)
	defer pool.Close()

	// Get a connection
	conn1, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn1)

	pool.ReleaseConnection(conn1)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Get connection again - should be a new one
	conn2, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn2)

	// Should be different connections due to expiration
	assert.NotEqual(t, conn1, conn2)

	pool.ReleaseConnection(conn2)
}

func TestUDPConnectionPoolClose(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(2, 1*time.Minute, logger)

	// Get a connection
	conn, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn)

	pool.ReleaseConnection(conn)

	// Close the pool
	err = pool.Close()
	assert.NoError(t, err)

	// Connection should be closed
	assert.Nil(t, conn.conn)
}

func TestTCPConnectionPool(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewTCPConnectionPool(2, 1*time.Minute, logger)
	defer pool.Close()

	// Mock server address (won't actually connect in this test)
	serverAddr := "localhost:1812"
	timeout := 1 * time.Second

	// Test getting a connection (will fail to connect but test structure)
	_, err := pool.GetConnection(serverAddr, timeout, nil)
	assert.Error(t, err) // Expected since we're not running a server
	assert.Contains(t, err.Error(), "failed to create TCP connection")
}

func TestTCPConnectionPoolClose(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewTCPConnectionPool(2, 1*time.Minute, logger)

	// Close the pool
	err := pool.Close()
	assert.NoError(t, err)
}

// TestRADSECConnectionPool - RADSEC functionality is now handled by TCP with TLS

// TestRADSECConnectionPoolClose - RADSEC functionality is now handled by TCP with TLS

func TestUDPClientWithPool(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(2, 1*time.Minute, logger)
	defer pool.Close()

	// Create UDP client with pool
	client, err := NewUDPClientWithPool("localhost:1812", []byte("secret"), 30*time.Second, pool, logger)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, pool, client.connPool)

	// Test setting local address
	client.SetLocalAddr("127.0.0.1:0")
	assert.Equal(t, "127.0.0.1:0", client.localAddr)

	client.Close()
}

func TestTCPClientWithPool(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewTCPConnectionPool(2, 1*time.Minute, logger)
	defer pool.Close()

	// Create TCP client with pool
	client, err := NewTCPClientWithPool("localhost:1812", []byte("secret"), 30*time.Second, pool, logger)
	assert.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, pool, client.connPool)

	// Test setting keep alive
	client.SetKeepAlive(false)
	assert.False(t, client.keepAlive)

	// Test setting max idle time
	client.SetMaxIdleTime(2 * time.Minute)
	assert.Equal(t, 2*time.Minute, client.maxIdleTime)

	client.Disconnect()
}

// TestRADSECClientWithPool - RADSEC functionality is now handled by TCP with TLS

// TestRADSECClientWithTLSAndPool - RADSEC functionality is now handled by TCP with TLS

func TestUDPPooledConnectionClose(t *testing.T) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(2, 1*time.Minute, logger)
	defer pool.Close()

	// Get a connection
	conn, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn)
	assert.NotNil(t, conn.conn)

	// Close the connection
	err = conn.Close()
	assert.NoError(t, err)
	assert.Nil(t, conn.conn)

	// Close again should not error
	err = conn.Close()
	assert.NoError(t, err)
}

func TestTCPPooledConnectionClose(t *testing.T) {
	// Create a mock TCP pooled connection
	conn := &TCPPooledConnection{
		conn: nil, // Simulate no connection
	}

	// Close should not error even with nil connection
	err := conn.Close()
	assert.NoError(t, err)
}

// TestRADSECPooledConnectionClose - RADSEC functionality is now handled by TCP with TLS

func TestConnectionPoolsCleanup(t *testing.T) {
	logger := log.NewDefaultLogger()

	// Create UDP pool with very short cleanup interval for testing
	pool := NewUDPConnectionPool(2, 50*time.Millisecond, logger)
	defer pool.Close()

	// Get and release a connection
	conn, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn)

	pool.ReleaseConnection(conn)

	// Wait for cleanup to potentially occur
	time.Sleep(100 * time.Millisecond)

	// Pool should still be functional
	conn2, err := pool.GetConnection(":0")
	assert.NoError(t, err)
	assert.NotNil(t, conn2)

	pool.ReleaseConnection(conn2)
}

// Benchmark tests for connection pools
func BenchmarkUDPConnectionPoolGetRelease(b *testing.B) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(10, 5*time.Minute, logger)
	defer pool.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := pool.GetConnection(":0")
		if err != nil {
			b.Fatal(err)
		}
		pool.ReleaseConnection(conn)
	}
}

func BenchmarkUDPConnectionPoolConcurrent(b *testing.B) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(10, 5*time.Minute, logger)
	defer pool.Close()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			conn, err := pool.GetConnection(":0")
			if err != nil {
				b.Fatal(err)
			}
			pool.ReleaseConnection(conn)
		}
	})
}

func BenchmarkUDPClientSendRequestWithPool(b *testing.B) {
	logger := log.NewDefaultLogger()
	pool := NewUDPConnectionPool(10, 5*time.Minute, logger)
	defer pool.Close()

	// Create UDP client with pool
	client, err := NewUDPClientWithPool("localhost:1812", []byte("secret"), 30*time.Second, pool, logger)
	if err != nil {
		b.Fatal(err)
	}
	defer client.Close()

	// Create test request
	req := packet.New(packet.CodeAccessRequest, 1)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// This will fail due to no server, but tests the pool path
		_, _ = client.SendRequest(context.Background(), req)
	}
}
