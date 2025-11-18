package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/packet"
)

type testHandler struct {
	mu           sync.Mutex
	secretCalled bool
	radiusCalled bool
	secretResp   SecretResponse
	secretErr    error
	radiusResp   Response
	radiusErr    error
}

func (h *testHandler) ServeSecret(_ SecretRequest) (SecretResponse, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.secretCalled = true
	return h.secretResp, h.secretErr
}

func (h *testHandler) ServeRADIUS(_ *Request) (Response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.radiusCalled = true
	return h.radiusResp, h.radiusErr
}

func (h *testHandler) WasSecretCalled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.secretCalled
}

func (h *testHandler) WasRADIUSCalled() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.radiusCalled
}

func (h *testHandler) SetRadiusResponse(resp Response) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.radiusResp = resp
}

func TestNew(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{}

	srv, err := New(":0", handler, dict)
	require.NoError(t, err)
	assert.NotNil(t, srv)
	assert.NotNil(t, srv.conn)
	assert.Equal(t, handler, srv.handler)
	assert.Equal(t, dict, srv.dict)

	srv.Close()
}

func TestNewInvalidAddress(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{}

	_, err := New("invalid:address:format", handler, dict)
	assert.Error(t, err)
}

func TestServerClose(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{}

	srv, err := New(":0", handler, dict)
	require.NoError(t, err)

	err = srv.Close()
	assert.NoError(t, err)
}

func TestServerServeStop(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{
		secretResp: SecretResponse{Secret: []byte("testing123")},
	}

	srv, err := New(":0", handler, dict)
	require.NoError(t, err)

	// Start server in background
	go func() {
		srv.Serve()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Close server
	err = srv.Close()
	assert.NoError(t, err)
}

func TestServerHandlePacket(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

	handler := &testHandler{
		secretResp: SecretResponse{Secret: []byte("testing123")},
	}

	srv, err := New(":0", handler, dict)
	require.NoError(t, err)
	defer srv.Close()

	// Start server in background
	go func() {
		srv.Serve()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Get server address
	serverAddr := srv.conn.LocalAddr().(*net.UDPAddr)

	// Create client connection
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Create a test packet
	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))

	// Set response for handler
	respPkt := packet.New(packet.CodeAccessAccept, 1)
	handler.SetRadiusResponse(Response{Packet: respPkt})

	// Encode packet
	data, err := pkt.Encode()
	require.NoError(t, err)

	// Send packet
	_, err = clientConn.Write(data)
	require.NoError(t, err)

	// Read response
	buffer := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := clientConn.Read(buffer)
	require.NoError(t, err)

	// Decode response
	respReceived, err := packet.Decode(buffer[:n])
	require.NoError(t, err)
	assert.Equal(t, packet.CodeAccessAccept, respReceived.Code)
	assert.Equal(t, uint8(1), respReceived.Identifier)

	// Verify handler was called (with timeout)
	time.Sleep(100 * time.Millisecond)
	assert.True(t, handler.WasSecretCalled())
	assert.True(t, handler.WasRADIUSCalled())
}

func TestServerWithDictionary(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

	handler := &testHandler{
		secretResp: SecretResponse{Secret: []byte("testing123")},
	}

	srv, err := New(":0", handler, dict)
	require.NoError(t, err)
	defer srv.Close()

	assert.Equal(t, dict, srv.dict)
}

func TestServerNilHandler(t *testing.T) {
	dict := dictionary.New()

	srv, err := New(":0", nil, dict)
	require.NoError(t, err)
	defer srv.Close()

	// Server should not crash with nil handler
	go func() {
		srv.Serve()
	}()

	time.Sleep(100 * time.Millisecond)

	// Send a packet (should be ignored)
	serverAddr := srv.conn.LocalAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	pkt := packet.New(packet.CodeAccessRequest, 1)
	data, _ := pkt.Encode()
	clientConn.Write(data)

	// Should not crash
	time.Sleep(100 * time.Millisecond)
}

func TestServerMiddleware(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{
		secretResp: SecretResponse{Secret: []byte("testing123")},
	}

	srv, err := New(":0", handler, dict)
	require.NoError(t, err)
	defer srv.Close()

	// Track middleware execution order
	var executionOrder []string
	mu := sync.Mutex{}

	// First middleware
	middleware1 := func(next Handler) Handler {
		return HandlerFunc(func(req *Request) (Response, error) {
			mu.Lock()
			executionOrder = append(executionOrder, "middleware1-before")
			mu.Unlock()

			resp, err := next.ServeRADIUS(req)

			mu.Lock()
			executionOrder = append(executionOrder, "middleware1-after")
			mu.Unlock()

			return resp, err
		})
	}

	// Second middleware
	middleware2 := func(next Handler) Handler {
		return HandlerFunc(func(req *Request) (Response, error) {
			mu.Lock()
			executionOrder = append(executionOrder, "middleware2-before")
			mu.Unlock()

			resp, err := next.ServeRADIUS(req)

			mu.Lock()
			executionOrder = append(executionOrder, "middleware2-after")
			mu.Unlock()

			return resp, err
		})
	}

	// Add middlewares
	srv.Use(middleware1)
	srv.Use(middleware2)

	// Set response for handler
	respPkt := packet.New(packet.CodeAccessAccept, 1)
	handler.SetRadiusResponse(Response{Packet: respPkt})

	// Start server
	go func() {
		srv.Serve()
	}()

	time.Sleep(100 * time.Millisecond)

	// Send request
	serverAddr := srv.conn.LocalAddr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
	data, err := pkt.Encode()
	require.NoError(t, err)

	_, err = clientConn.Write(data)
	require.NoError(t, err)

	// Read response
	buffer := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = clientConn.Read(buffer)
	require.NoError(t, err)

	// Verify middleware execution order
	time.Sleep(100 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()

	// Middlewares should execute in order: middleware1, middleware2, handler, middleware2, middleware1
	assert.Len(t, executionOrder, 4)
	assert.Equal(t, "middleware1-before", executionOrder[0])
	assert.Equal(t, "middleware2-before", executionOrder[1])
	assert.Equal(t, "middleware2-after", executionOrder[2])
	assert.Equal(t, "middleware1-after", executionOrder[3])
}
