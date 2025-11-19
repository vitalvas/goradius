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

type combinedTestHandler struct {
	secretResp    SecretResponse
	radiusHandler Handler
}

func (h *combinedTestHandler) ServeSecret(_ SecretRequest) (SecretResponse, error) {
	return h.secretResp, nil
}

func (h *combinedTestHandler) ServeRADIUS(req *Request) (Response, error) {
	return h.radiusHandler.ServeRADIUS(req)
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

	srv, err := New(Config{
		Addr:       ":0",
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)
	assert.NotNil(t, srv)
	assert.Equal(t, ":0", srv.addr)
	assert.Equal(t, handler, srv.handler)
	assert.Equal(t, dict, srv.dict)

	srv.Close()
}

func TestNewInvalidAddress(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{}

	srv, err := New(Config{
		Addr:       "invalid:address:format",
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)
	assert.NotNil(t, srv)

	err = srv.ListenAndServe()
	assert.Error(t, err)
}

func TestServerClose(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{}

	srv, err := New(Config{
		Addr:       ":0",
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	err = srv.Close()
	assert.NoError(t, err)
}

func TestServerServeStop(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{
		secretResp: SecretResponse{Secret: []byte("testing123")},
	}

	srv, err := New(Config{
		Addr:       ":0",
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	// Start server in background
	go func() {
		srv.ListenAndServe()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Close server
	err = srv.Close()
	assert.NoError(t, err)
}

func TestServerHandlePacket(t *testing.T) {
	dict := dictionary.New()
	require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

	handler := &testHandler{
		secretResp: SecretResponse{Secret: []byte("testing123")},
	}

	srv, err := New(Config{
		Addr:       ":0",
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)
	defer srv.Close()

	// Start server in background
	go func() {
		srv.ListenAndServe()
	}()

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Get server address
	serverAddr := srv.Addr().(*net.UDPAddr)

	// Create client connection
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Create a test packet
	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
	pkt.AddMessageAuthenticator([]byte("testing123"), pkt.Authenticator)

	// Set response for handler
	respPkt := packet.New(packet.CodeAccessAccept, 1)
	handler.SetRadiusResponse(Response{packet: respPkt})

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
	require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

	handler := &testHandler{
		secretResp: SecretResponse{Secret: []byte("testing123")},
	}

	srv, err := New(Config{
		Addr:       ":0",
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)
	defer srv.Close()

	assert.Equal(t, dict, srv.dict)
}

func TestServerNilDictionary(t *testing.T) {
	handler := &testHandler{}

	srv, err := New(Config{
		Addr:    ":0",
		Handler: handler,
	})
	require.NoError(t, err)
	defer srv.Close()

	assert.NotNil(t, srv.dict)
}

func TestServerNilHandler(t *testing.T) {
	dict := dictionary.New()

	srv, err := New(Config{
		Addr:       ":0",
		Handler:    nil,
		Dictionary: dict,
	})
	require.NoError(t, err)
	defer srv.Close()

	// Server should not crash with nil handler
	go func() {
		srv.ListenAndServe()
	}()

	time.Sleep(100 * time.Millisecond)

	// Send a packet (should be ignored)
	serverAddr := srv.Addr().(*net.UDPAddr)
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

	srv, err := New(Config{
		Addr:       ":0",
		Handler:    handler,
		Dictionary: dict,
	})
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
	handler.SetRadiusResponse(Response{packet: respPkt})

	// Start server
	go func() {
		srv.ListenAndServe()
	}()

	time.Sleep(100 * time.Millisecond)

	// Send request
	serverAddr := srv.Addr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
	pkt.AddMessageAuthenticator([]byte("testing123"), pkt.Authenticator)
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

// Benchmarks

func BenchmarkServerHandlePacket(b *testing.B) {
	dict, _ := dictionaries.NewDefault()
	secret := []byte("testing123")

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
	}

	srv, _ := New(Config{
		Addr:       ":0",
		Handler:    handler,
		Dictionary: dict,
	})

	// Create Access-Request packet
	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	_ = reqPkt.AddAttributeByName("User-Name", "testuser")
	_ = reqPkt.AddAttributeByName("NAS-IP-Address", "192.168.1.1")

	reqAuth := reqPkt.CalculateRequestAuthenticator(secret)
	reqPkt.SetAuthenticator(reqAuth)
	reqPkt.AddMessageAuthenticator(secret, reqAuth)

	data, _ := reqPkt.Encode()

	// Create UDP connection for testing
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer conn.Close()
	srv.conn = conn
	close(srv.ready)

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			// Create fresh response packet for each iteration
			respPkt := packet.NewWithDictionary(packet.CodeAccessAccept, 1, dict)
			_ = respPkt.AddAttributeByName("Session-Timeout", uint32(3600))
			handler.SetRadiusResponse(Response{packet: respPkt})

			// Copy data for concurrent access
			dataCopy := make([]byte, len(data))
			copy(dataCopy, data)
			srv.handlePacket(dataCopy, clientAddr)
		}
	})
}

func BenchmarkNewResponse(b *testing.B) {
	dict, _ := dictionaries.NewDefault()

	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	req := &Request{
		packet: reqPkt,
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = NewResponse(req)
	}
}

func BenchmarkServerBuildHandler(b *testing.B) {
	handler := &testHandler{}

	srv := &Server{
		handler: handler,
	}

	// Add multiple middlewares
	for i := 0; i < 5; i++ {
		srv.Use(func(next Handler) Handler {
			return HandlerFunc(func(r *Request) (Response, error) {
				return next.ServeRADIUS(r)
			})
		})
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = srv.buildHandler()
	}
}

func BenchmarkE2EServerRequestResponse(b *testing.B) {
	dict, _ := dictionaries.NewDefault()
	secret := []byte("testing123")

	// Use a handler function that creates fresh response each time
	handler := HandlerFunc(func(req *Request) (Response, error) {
		respPkt := packet.NewWithDictionary(packet.CodeAccessAccept, req.packet.Identifier, dict)
		_ = respPkt.AddAttributeByName("Session-Timeout", uint32(3600))
		return Response{packet: respPkt}, nil
	})

	// Wrap handlers to combine secret and radius handling
	combinedHandler := &combinedTestHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusHandler: handler,
	}

	srv, _ := New(Config{
		Addr:       ":0",
		Handler:    combinedHandler,
		Dictionary: dict,
	})

	// Start server
	go srv.ListenAndServe()
	time.Sleep(10 * time.Millisecond) // Wait for server to start

	addr := srv.Addr().(*net.UDPAddr)
	clientConn, _ := net.DialUDP("udp", nil, addr)
	defer clientConn.Close()
	defer srv.Close()

	// Pre-create request packet
	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	_ = reqPkt.AddAttributeByName("User-Name", "testuser")
	_ = reqPkt.AddAttributeByName("NAS-IP-Address", "192.168.1.1")

	reqAuth := reqPkt.CalculateRequestAuthenticator(secret)
	reqPkt.SetAuthenticator(reqAuth)
	reqPkt.AddMessageAuthenticator(secret, reqAuth)

	reqData, _ := reqPkt.Encode()

	// Reuse response buffer
	respData := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		// Send request
		clientConn.Write(reqData)

		// Receive response
		clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		_, _ = clientConn.Read(respData)
	}
}

func BenchmarkE2EServerRequestResponseParallel(b *testing.B) {
	dict, _ := dictionaries.NewDefault()
	secret := []byte("testing123")

	// Use a handler function that creates fresh response each time
	handler := HandlerFunc(func(req *Request) (Response, error) {
		respPkt := packet.NewWithDictionary(packet.CodeAccessAccept, req.packet.Identifier, dict)
		_ = respPkt.AddAttributeByName("Session-Timeout", uint32(3600))
		return Response{packet: respPkt}, nil
	})

	// Wrap handlers to combine secret and radius handling
	combinedHandler := &combinedTestHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusHandler: handler,
	}

	srv, _ := New(Config{
		Addr:       ":0",
		Handler:    combinedHandler,
		Dictionary: dict,
	})

	// Start server
	go srv.ListenAndServe()
	time.Sleep(10 * time.Millisecond)

	// Pre-create request packet
	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	_ = reqPkt.AddAttributeByName("User-Name", "testuser")
	_ = reqPkt.AddAttributeByName("NAS-IP-Address", "192.168.1.1")

	reqAuth := reqPkt.CalculateRequestAuthenticator(secret)
	reqPkt.SetAuthenticator(reqAuth)
	reqPkt.AddMessageAuthenticator(secret, reqAuth)

	reqData, _ := reqPkt.Encode()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		addr := srv.Addr().(*net.UDPAddr)
		clientConn, _ := net.DialUDP("udp", nil, addr)
		defer clientConn.Close()

		// Reuse response buffer
		respData := make([]byte, 4096)

		for pb.Next() {
			clientConn.Write(reqData)

			clientConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			_, _ = clientConn.Read(respData)
		}
	})

	srv.Close()
}
