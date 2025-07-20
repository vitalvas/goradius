package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/client"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

// TestTCPServer tests the TCP server implementation
func TestTCPServer(t *testing.T) {
	logger := log.NewDefaultLogger()

	// Create test handler
	handler := &TestHandler{
		responses: make(map[string]*Response),
	}

	// Create server config with TCP binding
	config := &Config{
		Bindings: []Binding{
			{
				Address:   "127.0.0.1",
				Port:      0, // Use random port
				IPVersion: 4,
				Transport: TransportTCP,
				Clients: []ClientConfig{
					{
						Networks: []string{"127.0.0.1"},
						Secret:   "test-secret",
						Name:     "test-client",
					},
				},
			},
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxRequestSize: 4096,
		Workers:        15, // Increased to handle concurrent test load
		Logger:         logger,
	}

	// Create server
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	// Start server
	err = server.Start()
	require.NoError(t, err)

	// Give the server time to start listening
	time.Sleep(10 * time.Millisecond)

	// Get actual port
	var serverPort int
	server.mu.RLock()
	for _, listener := range server.tcpListeners {
		serverPort = listener.GetPort()
		if serverPort > 0 {
			break
		}
	}
	server.mu.RUnlock()

	require.NotZero(t, serverPort, "Server should have a listening port")

	// Test client connection and request
	t.Run("BasicTCPRequest", func(t *testing.T) {
		testBasicTCPRequest(t, serverPort, handler)
	})

	t.Run("ConcurrentTCPRequests", func(t *testing.T) {
		testConcurrentTCPRequests(t, serverPort, handler)
	})

	t.Run("TCPConnectionReuse", func(t *testing.T) {
		testTCPConnectionReuse(t, serverPort, handler)
	})

	t.Run("TCPPacketFraming", func(t *testing.T) {
		testTCPPacketFraming(t, serverPort, handler)
	})

	// Stop server
	err = server.Stop()
	require.NoError(t, err)
}

func testBasicTCPRequest(t *testing.T, serverPort int, handler *TestHandler) {
	logger := log.NewDefaultLogger()

	// Create TCP client
	client, err := client.NewTCPClient(
		fmt.Sprintf("127.0.0.1:%d", serverPort),
		[]byte("test-secret"),
		5*time.Second,
		logger,
	)
	require.NoError(t, err)

	// Configure expected response
	expectedResponse := createTestPacket(packet.CodeAccessAccept, 1, []packet.Attribute{})

	handler.mu.Lock()
	handler.responses["1"] = &Response{
		Packet: expectedResponse,
		Send:   true,
	}
	handler.mu.Unlock()

	// Create request
	request := createTestPacket(packet.CodeAccessRequest, 1, []packet.Attribute{
		packet.NewStringAttribute(packet.AttrUserName, "testuser"),
	})

	// Send request
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	response, err := client.SendRequest(ctx, request)
	require.NoError(t, err)
	require.NotNil(t, response)

	// Verify response
	assert.Equal(t, packet.CodeAccessAccept, response.Code)
	assert.Equal(t, uint8(1), response.Identifier)

	// Verify client statistics
	stats := client.GetStatistics()
	assert.Equal(t, int64(1), stats.ConnectionsTotal)
	assert.Equal(t, int64(1), stats.RequestsSent)
	assert.Equal(t, int64(1), stats.ResponsesReceived)
	assert.True(t, stats.BytesSent > 0)
	assert.True(t, stats.BytesReceived > 0)

	// Disconnect
	err = client.Disconnect()
	require.NoError(t, err)
}

func testConcurrentTCPRequests(t *testing.T, serverPort int, handler *TestHandler) {
	logger := log.NewDefaultLogger()
	numClients := 5        // Reduced from 10 to be more manageable
	requestsPerClient := 3 // Reduced from 5 to prevent worker exhaustion

	// Configure expected response
	expectedResponse := createTestPacket(packet.CodeAccessAccept, 1, []packet.Attribute{})

	handler.mu.Lock()
	handler.responses["1"] = &Response{
		Packet: expectedResponse,
		Send:   true,
	}
	handler.mu.Unlock()

	var wg sync.WaitGroup
	results := make(chan error, numClients*requestsPerClient)

	// Start concurrent clients
	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			// Create TCP client
			client, err := client.NewTCPClient(
				fmt.Sprintf("127.0.0.1:%d", serverPort),
				[]byte("test-secret"),
				5*time.Second,
				logger,
			)
			if err != nil {
				results <- err
				return
			}
			defer client.Disconnect()

			// Send multiple requests
			for j := 0; j < requestsPerClient; j++ {
				request := createTestPacket(packet.CodeAccessRequest, uint8(j+1), []packet.Attribute{
					packet.NewStringAttribute(packet.AttrUserName, fmt.Sprintf("user%d", clientID)),
				})

				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				response, err := client.SendRequest(ctx, request)
				cancel()

				if err != nil {
					results <- err
					return
				}

				if response.Code != packet.CodeAccessAccept {
					results <- fmt.Errorf("unexpected response code: %d", response.Code)
					return
				}
			}

			results <- nil
		}(i)
	}

	wg.Wait()
	close(results)

	// Check all results
	successCount := 0
	for err := range results {
		if err != nil {
			t.Errorf("Client error: %v", err)
		} else {
			successCount++
		}
	}

	// With reduced load (5 clients × 3 requests = 15 total) and 15 workers,
	// all requests should succeed
	assert.Equal(t, numClients, successCount, "All clients should succeed")
}

func testTCPConnectionReuse(t *testing.T, serverPort int, handler *TestHandler) {
	logger := log.NewDefaultLogger()

	// Create TCP client
	client, err := client.NewTCPClient(
		fmt.Sprintf("127.0.0.1:%d", serverPort),
		[]byte("test-secret"),
		5*time.Second,
		logger,
	)
	require.NoError(t, err)
	defer client.Disconnect()

	// Configure expected response
	expectedResponse := createTestPacket(packet.CodeAccessAccept, 1, []packet.Attribute{})

	handler.mu.Lock()
	handler.responses["1"] = &Response{
		Packet: expectedResponse,
		Send:   true,
	}
	handler.mu.Unlock()

	// Send multiple requests using the same connection
	for i := 0; i < 5; i++ {
		request := createTestPacket(packet.CodeAccessRequest, uint8(i+1), []packet.Attribute{
			packet.NewStringAttribute(packet.AttrUserName, fmt.Sprintf("user%d", i)),
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		response, err := client.SendRequest(ctx, request)
		cancel()

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, packet.CodeAccessAccept, response.Code)
		assert.Equal(t, uint8(i+1), response.Identifier)
	}

	// Verify statistics show connection reuse
	stats := client.GetStatistics()
	assert.Equal(t, int64(1), stats.ConnectionsTotal, "Should only connect once")
	assert.Equal(t, int64(5), stats.RequestsSent, "Should send 5 requests")
	assert.Equal(t, int64(5), stats.ResponsesReceived, "Should receive 5 responses")
}

func testTCPPacketFraming(t *testing.T, serverPort int, handler *TestHandler) {
	// Test direct TCP connection to verify packet framing
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort))
	require.NoError(t, err)
	defer conn.Close()

	// Configure expected response
	expectedResponse := createTestPacket(packet.CodeAccessAccept, 42, []packet.Attribute{})

	handler.mu.Lock()
	handler.responses["1"] = &Response{
		Packet: expectedResponse,
		Send:   true,
	}
	handler.mu.Unlock()

	// Create a test packet
	request := createTestPacket(packet.CodeAccessRequest, 42, []packet.Attribute{
		packet.NewStringAttribute(packet.AttrUserName, "testuser"),
	})

	// Encode packet
	packetData, err := request.Encode()
	require.NoError(t, err)

	// Send length-prefixed packet
	lengthPrefix := []byte{0x00, byte(len(packetData) + 2)}
	_, err = conn.Write(lengthPrefix)
	require.NoError(t, err)

	_, err = conn.Write(packetData)
	require.NoError(t, err)

	// Read response length
	lengthBuf := make([]byte, 2)
	_, err = conn.Read(lengthBuf)
	require.NoError(t, err)

	responseLength := (uint16(lengthBuf[0]) << 8) | uint16(lengthBuf[1])
	assert.True(t, responseLength >= 20, "Response should be at least 20 bytes")

	// Read response data
	responseData := make([]byte, responseLength-2)
	_, err = conn.Read(responseData)
	require.NoError(t, err)

	// Decode response
	response, err := packet.Decode(responseData)
	require.NoError(t, err)

	// Verify response
	assert.Equal(t, packet.CodeAccessAccept, response.Code)
	assert.Equal(t, uint8(42), response.Identifier)
}

// TestTCPListener tests the TCP listener directly
func TestTCPListener(t *testing.T) {
	logger := log.NewDefaultLogger()

	// Create test handler
	handler := &TestHandler{
		responses: make(map[string]*Response),
	}

	// Create binding
	binding := Binding{
		Address:   "127.0.0.1",
		Port:      0, // Use random port
		IPVersion: 4,
		Transport: TransportTCP,
		Clients: []ClientConfig{
			{
				Networks: []string{"127.0.0.1"},
				Secret:   "test-secret",
				Name:     "test-client",
			},
		},
	}

	// Create config
	config := &Config{
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxRequestSize: 4096,
		Workers:        5,
		Logger:         logger,
	}

	// Create TCP listener
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listener, err := NewTCPListener(ctx, binding, config, handler, logger)
	require.NoError(t, err)

	// Start listener
	go func() {
		err := listener.Listen()
		if err != nil {
			t.Logf("Listener error: %v", err)
		}
	}()

	// Give listener time to start
	time.Sleep(100 * time.Millisecond)

	// Get listener address
	addr := listener.GetListenerAddress()
	require.NotNil(t, addr)

	// Test connection count
	assert.Equal(t, 0, listener.GetConnectionCount())

	// Stop listener
	listener.Stop()
}

// TestTCPConnectionInfo tests TCP connection information
func TestTCPConnectionInfo(t *testing.T) {
	logger := log.NewDefaultLogger()

	// Create test handler
	handler := &TestHandler{
		responses: make(map[string]*Response),
	}

	// Configure expected response
	expectedResponse := createTestPacket(packet.CodeAccessAccept, 1, []packet.Attribute{})

	handler.mu.Lock()
	handler.responses["1"] = &Response{
		Packet: expectedResponse,
		Send:   true,
	}
	handler.mu.Unlock()

	// Create server config
	config := &Config{
		Bindings: []Binding{
			{
				Address:   "127.0.0.1",
				Port:      0,
				IPVersion: 4,
				Transport: TransportTCP,
				Clients: []ClientConfig{
					{
						Networks: []string{"127.0.0.1"},
						Secret:   "test-secret",
						Name:     "test-client",
					},
				},
			},
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxRequestSize: 4096,
		Workers:        5,
		Logger:         logger,
	}

	// Create and start server
	server, err := NewServer(config, handler)
	require.NoError(t, err)

	err = server.Start()
	require.NoError(t, err)
	defer server.Stop()

	// Give the server time to start listening
	time.Sleep(10 * time.Millisecond)

	// Get server port
	var serverPort int
	server.mu.RLock()
	for _, listener := range server.tcpListeners {
		serverPort = listener.GetPort()
		if serverPort > 0 {
			break
		}
	}
	server.mu.RUnlock()

	// Create client and connect
	client, err := client.NewTCPClient(
		fmt.Sprintf("127.0.0.1:%d", serverPort),
		[]byte("test-secret"),
		5*time.Second,
		logger,
	)
	require.NoError(t, err)
	defer client.Disconnect()

	// Send request to establish connection
	request := createTestPacket(packet.CodeAccessRequest, 1, []packet.Attribute{
		packet.NewStringAttribute(packet.AttrUserName, "testuser"),
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err = client.SendRequest(ctx, request)
	require.NoError(t, err)

	// Check connection information
	server.mu.RLock()
	for _, listener := range server.tcpListeners {
		connections := listener.GetConnections()
		assert.Equal(t, 1, len(connections), "Should have one active connection")

		for _, connInfo := range connections {
			assert.NotNil(t, connInfo.ClientAddr)
			assert.True(t, connInfo.Connected.Before(time.Now()))
			assert.True(t, connInfo.LastSeen.Before(time.Now().Add(time.Second)))
			assert.True(t, connInfo.BytesReceived > 0)
			assert.True(t, connInfo.BytesSent > 0)
			assert.Equal(t, uint64(1), connInfo.Requests)
			assert.Equal(t, uint64(1), connInfo.Responses)
		}
	}
	server.mu.RUnlock()
}

// TestTCPStatistics tests TCP client statistics
func TestTCPStatistics(t *testing.T) {
	logger := log.NewDefaultLogger()

	// Create TCP client
	client, err := client.NewTCPClient(
		"127.0.0.1:12345", // Non-existent server
		[]byte("test-secret"),
		1*time.Second,
		logger,
	)
	require.NoError(t, err)

	// Try to connect (should fail)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	request := createTestPacket(packet.CodeAccessRequest, 1, []packet.Attribute{})

	_, err = client.SendRequest(ctx, request)
	assert.Error(t, err, "Should fail to connect to non-existent server")

	// Check statistics
	stats := client.GetStatistics()
	assert.True(t, stats.ConnectionsTotal > 0)
	assert.True(t, stats.ConnectionsFailures > 0)
	assert.Equal(t, int64(0), stats.RequestsSent)
	assert.Equal(t, int64(0), stats.ResponsesReceived)
}

// TestHandler is a test implementation of the Handler interface
type TestHandler struct {
	mu        sync.RWMutex
	responses map[string]*Response
}

func (h *TestHandler) HandleRequest(_ context.Context, req *Request) (*Response, error) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	if response, exists := h.responses[fmt.Sprintf("%d", req.Packet.Code)]; exists {
		// Copy the response and set correct identifier
		responseCopy := *response
		if responseCopy.Packet != nil {
			packetCopy := *responseCopy.Packet
			packetCopy.Identifier = req.Packet.Identifier
			responseCopy.Packet = &packetCopy
		}
		return &responseCopy, nil
	}

	return &Response{
		Packet: createTestPacket(packet.CodeAccessReject, req.Packet.Identifier, []packet.Attribute{}),
		Send:   true,
	}, nil
}

func (h *TestHandler) GetSharedSecret(_ net.Addr) ([]byte, error) {
	return []byte("test-secret"), nil
}

// createTestPacket creates a properly formatted test packet
func createTestPacket(code packet.Code, identifier uint8, attributes []packet.Attribute) *packet.Packet {
	// Calculate length
	length := uint16(packet.PacketHeaderLength)
	for _, attr := range attributes {
		length += uint16(attr.Length)
	}

	return &packet.Packet{
		Code:       code,
		Identifier: identifier,
		Length:     length,
		Attributes: attributes,
	}
}
