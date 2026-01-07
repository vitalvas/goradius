package server

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
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

func (h *testHandler) ServeRADIUS(req *Request) (Response, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.radiusCalled = true

	if h.radiusResp.packet != nil {
		respPkt := packet.New(h.radiusResp.packet.Code, req.packet.Identifier)
		return Response{packet: respPkt}, h.radiusErr
	}

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

// startTestServer creates a UDP transport and starts the server, returning the transport for cleanup
func startTestServer(tb testing.TB, srv *Server) *UDPTransport {
	tb.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		tb.Fatalf("failed to create UDP listener: %v", err)
	}
	transport := NewUDPTransport(conn)
	go srv.Serve(transport)
	time.Sleep(50 * time.Millisecond) // Give server time to start
	return transport
}

func TestNew(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{}

	srv, err := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)
	assert.NotNil(t, srv)
	assert.Equal(t, handler, srv.handler)
	assert.Equal(t, dict, srv.dict)

	srv.Close()
}


func TestServerClose(t *testing.T) {
	dict := dictionary.New()
	handler := &testHandler{}

	srv, err := New(Config{
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
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	// Start server in background
	startTestServer(t, srv)

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
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)
	defer srv.Close()

	// Start server in background
	startTestServer(t, srv)

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
		Handler: handler,
	})
	require.NoError(t, err)
	defer srv.Close()

	assert.NotNil(t, srv.dict)
}

func TestServerNilHandler(t *testing.T) {
	dict := dictionary.New()

	srv, err := New(Config{
		Handler:    nil,
		Dictionary: dict,
	})
	require.NoError(t, err)
	defer srv.Close()

	// Server should not crash with nil handler
	startTestServer(t, srv)

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
	startTestServer(t, srv)

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

	// Create UDP connection and transport for testing
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	defer conn.Close()
	transport := NewUDPTransport(conn)
	srv.transport = transport
	close(srv.ready)

	clientAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345}

	// Create a no-op responder for benchmarking
	respond := func(_ []byte) error {
		return nil
	}

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
			srv.handlePacket(dataCopy, clientAddr, respond)
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
		secretResp:    SecretResponse{Secret: secret},
		radiusHandler: handler,
	}

	srv, _ := New(Config{
		Handler:    combinedHandler,
		Dictionary: dict,
	})

	// Start server
	startTestServer(b, srv)

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
		secretResp:    SecretResponse{Secret: secret},
		radiusHandler: handler,
	}

	srv, _ := New(Config{
		Handler:    combinedHandler,
		Dictionary: dict,
	})

	// Start server
	startTestServer(b, srv)

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

func TestServerStressWithHighPacketRate(t *testing.T) {
	secret := []byte("testing123")
	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 0)},
	}

	srv, err := New(Config{
		Handler: handler,
	})
	assert.NoError(t, err)

	startTestServer(t, srv)
	defer srv.Close()

	addr := srv.Addr().(*net.UDPAddr)

	numPackets := 1000
	var wg sync.WaitGroup
	errors := make(chan error, numPackets)

	for i := 0; i < numPackets; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			pkt := packet.New(packet.CodeAccessRequest, uint8(id%256))
			pkt.AddMessageAuthenticator(secret, pkt.Authenticator)

			data, err := pkt.Encode()
			if err != nil {
				errors <- err
				return
			}

			conn, err := net.DialUDP("udp", nil, addr)
			if err != nil {
				errors <- err
				return
			}
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(5 * time.Second))

			if _, err := conn.Write(data); err != nil {
				errors <- err
				return
			}

			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if err != nil {
				errors <- err
				return
			}

			_, err = packet.Decode(buffer[:n])
			if err != nil {
				errors <- err
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	errorCount := 0
	for err := range errors {
		if err != nil {
			t.Logf("Error: %v", err)
			errorCount++
		}
	}

	assert.Less(t, errorCount, numPackets/10, "Too many errors in stress test")
}

func TestServerConcurrentPackets(t *testing.T) {
	secret := []byte("testing123")
	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 0)},
	}

	srv, err := New(Config{
		Handler: handler,
	})
	assert.NoError(t, err)

	startTestServer(t, srv)
	defer srv.Close()

	addr := srv.Addr().(*net.UDPAddr)

	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			pkt := packet.New(packet.CodeAccessRequest, uint8(id))
			pkt.AddMessageAuthenticator(secret, pkt.Authenticator)

			data, _ := pkt.Encode()

			conn, _ := net.DialUDP("udp", nil, addr)
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Write(data)

			buffer := make([]byte, 4096)
			conn.Read(buffer)
		}(i)
	}

	wg.Wait()
}

func TestServerBufferSafety(t *testing.T) {
	secret := []byte("testing123")
	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 0)},
	}

	srv, err := New(Config{
		Handler: handler,
	})
	assert.NoError(t, err)

	startTestServer(t, srv)
	defer srv.Close()

	addr := srv.Addr().(*net.UDPAddr)

	packets := make([]*packet.Packet, 50)
	for i := range packets {
		pkt := packet.New(packet.CodeAccessRequest, uint8(i))
		pkt.AddMessageAuthenticator(secret, pkt.Authenticator)
		packets[i] = pkt
	}

	var wg sync.WaitGroup
	for i, pkt := range packets {
		wg.Add(1)
		go func(_ int, p *packet.Packet) {
			defer wg.Done()

			data, _ := p.Encode()

			conn, _ := net.DialUDP("udp", nil, addr)
			defer conn.Close()

			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Write(data)

			buffer := make([]byte, 4096)
			n, err := conn.Read(buffer)
			if err != nil {
				return
			}

			respPkt, err := packet.Decode(buffer[:n])
			if err != nil {
				return
			}

			assert.Equal(t, p.Identifier, respPkt.Identifier)
		}(i, pkt)
	}

	wg.Wait()
}

func TestServerRequestAuthenticatorValidation(t *testing.T) {
	t.Run("disabled_accepts_invalid_authenticator", func(t *testing.T) {
		dict := dictionary.New()
		require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

		secret := []byte("testing123")
		handler := &testHandler{
			secretResp: SecretResponse{Secret: secret},
		}

		// RequireRequestAuthenticator defaults to false
		srv, err := New(Config{
			Handler:    handler,
			Dictionary: dict,
		})
		require.NoError(t, err)
		defer srv.Close()

		startTestServer(t, srv)

		serverAddr := srv.Addr().(*net.UDPAddr)
		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		require.NoError(t, err)
		defer clientConn.Close()

		// Create Accounting-Request with INVALID (random) Request Authenticator
		pkt := packet.New(packet.CodeAccountingRequest, 1)
		pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
		// Set random authenticator (invalid for Accounting-Request per RFC 2866)
		var randomAuth [16]byte
		copy(randomAuth[:], []byte("invalidauthenti"))
		pkt.SetAuthenticator(randomAuth)
		pkt.AddMessageAuthenticator(secret, pkt.Authenticator)

		respPkt := packet.New(packet.CodeAccountingResponse, 1)
		handler.SetRadiusResponse(Response{packet: respPkt})

		data, err := pkt.Encode()
		require.NoError(t, err)

		_, err = clientConn.Write(data)
		require.NoError(t, err)

		buffer := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := clientConn.Read(buffer)
		require.NoError(t, err, "Should accept packet when RequireRequestAuthenticator is false")

		respReceived, err := packet.Decode(buffer[:n])
		require.NoError(t, err)
		assert.Equal(t, packet.CodeAccountingResponse, respReceived.Code)
	})

	t.Run("enabled_rejects_invalid_authenticator", func(t *testing.T) {
		dict := dictionary.New()
		require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

		secret := []byte("testing123")
		handler := &testHandler{
			secretResp: SecretResponse{Secret: secret},
		}

		requireRequestAuth := true
		srv, err := New(Config{
			Handler:                     handler,
			Dictionary:                  dict,
			RequireRequestAuthenticator: &requireRequestAuth,
		})
		require.NoError(t, err)
		defer srv.Close()

		startTestServer(t, srv)

		serverAddr := srv.Addr().(*net.UDPAddr)
		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		require.NoError(t, err)
		defer clientConn.Close()

		// Create Accounting-Request with INVALID (random) Request Authenticator
		pkt := packet.New(packet.CodeAccountingRequest, 1)
		pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
		var randomAuth [16]byte
		copy(randomAuth[:], []byte("invalidauthenti"))
		pkt.SetAuthenticator(randomAuth)
		pkt.AddMessageAuthenticator(secret, pkt.Authenticator)

		respPkt := packet.New(packet.CodeAccountingResponse, 1)
		handler.SetRadiusResponse(Response{packet: respPkt})

		data, err := pkt.Encode()
		require.NoError(t, err)

		_, err = clientConn.Write(data)
		require.NoError(t, err)

		buffer := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = clientConn.Read(buffer)
		assert.Error(t, err, "Should timeout/reject packet when RequireRequestAuthenticator is true")
	})

	t.Run("enabled_accepts_valid_authenticator", func(t *testing.T) {
		dict := dictionary.New()
		require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

		secret := []byte("testing123")
		handler := &testHandler{
			secretResp: SecretResponse{Secret: secret},
		}

		requireRequestAuth := true
		requireMessageAuth := false // Disable Message-Authenticator for this test
		srv, err := New(Config{
			Handler:                     handler,
			Dictionary:                  dict,
			RequireRequestAuthenticator: &requireRequestAuth,
			RequireMessageAuthenticator: &requireMessageAuth,
		})
		require.NoError(t, err)
		defer srv.Close()

		startTestServer(t, srv)

		serverAddr := srv.Addr().(*net.UDPAddr)
		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		require.NoError(t, err)
		defer clientConn.Close()

		// Create Accounting-Request with VALID computed Request Authenticator
		// RFC 2866: Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Attributes + Secret)
		pkt := packet.New(packet.CodeAccountingRequest, 1)
		pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
		// Calculate and set correct Request Authenticator per RFC 2866
		pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(secret))

		respPkt := packet.New(packet.CodeAccountingResponse, 1)
		handler.SetRadiusResponse(Response{packet: respPkt})

		data, err := pkt.Encode()
		require.NoError(t, err)

		_, err = clientConn.Write(data)
		require.NoError(t, err)

		buffer := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := clientConn.Read(buffer)
		require.NoError(t, err, "Should accept packet with valid Request Authenticator")

		respReceived, err := packet.Decode(buffer[:n])
		require.NoError(t, err)
		assert.Equal(t, packet.CodeAccountingResponse, respReceived.Code)
	})

	t.Run("both_enabled_accepts_valid_packet", func(t *testing.T) {
		dict := dictionary.New()
		require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

		secret := []byte("testing123")
		handler := &testHandler{
			secretResp: SecretResponse{Secret: secret},
		}

		requireRequestAuth := true
		requireMessageAuth := true
		srv, err := New(Config{
			Handler:                     handler,
			Dictionary:                  dict,
			RequireRequestAuthenticator: &requireRequestAuth,
			RequireMessageAuthenticator: &requireMessageAuth,
		})
		require.NoError(t, err)
		defer srv.Close()

		startTestServer(t, srv)

		serverAddr := srv.Addr().(*net.UDPAddr)
		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		require.NoError(t, err)
		defer clientConn.Close()

		// Create Accounting-Request with both valid Request Authenticator and Message-Authenticator
		pkt := packet.New(packet.CodeAccountingRequest, 1)
		pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))

		// Add Message-Authenticator placeholder (affects packet length for Request Authenticator calculation)
		pkt.AddMessageAuthenticator(secret, [16]byte{})

		// Calculate Request Authenticator with Message-Authenticator placeholder included
		pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(secret))

		// Recalculate Message-Authenticator with the computed Request Authenticator
		pkt.RemoveAttributes(packet.AttributeTypeMessageAuthenticator)
		pkt.AddMessageAuthenticator(secret, pkt.Authenticator)

		respPkt := packet.New(packet.CodeAccountingResponse, 1)
		handler.SetRadiusResponse(Response{packet: respPkt})

		data, err := pkt.Encode()
		require.NoError(t, err)

		_, err = clientConn.Write(data)
		require.NoError(t, err)

		buffer := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := clientConn.Read(buffer)
		require.NoError(t, err, "Should accept packet with both valid Request Authenticator and Message-Authenticator")

		respReceived, err := packet.Decode(buffer[:n])
		require.NoError(t, err)
		assert.Equal(t, packet.CodeAccountingResponse, respReceived.Code)
	})

	t.Run("both_enabled_rejects_invalid_message_auth", func(t *testing.T) {
		dict := dictionary.New()
		require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

		secret := []byte("testing123")
		handler := &testHandler{
			secretResp: SecretResponse{Secret: secret},
		}

		requireRequestAuth := true
		requireMessageAuth := true
		srv, err := New(Config{
			Handler:                     handler,
			Dictionary:                  dict,
			RequireRequestAuthenticator: &requireRequestAuth,
			RequireMessageAuthenticator: &requireMessageAuth,
		})
		require.NoError(t, err)
		defer srv.Close()

		startTestServer(t, srv)

		serverAddr := srv.Addr().(*net.UDPAddr)
		clientConn, err := net.DialUDP("udp", nil, serverAddr)
		require.NoError(t, err)
		defer clientConn.Close()

		// Create Accounting-Request with valid Request Authenticator but INVALID Message-Authenticator
		pkt := packet.New(packet.CodeAccountingRequest, 1)
		pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))

		// Calculate valid Request Authenticator first (without Message-Authenticator)
		pkt.SetAuthenticator(pkt.CalculateRequestAuthenticator(secret))

		// Add INVALID Message-Authenticator (wrong secret)
		pkt.AddMessageAuthenticator([]byte("wrongsecret"), pkt.Authenticator)

		respPkt := packet.New(packet.CodeAccountingResponse, 1)
		handler.SetRadiusResponse(Response{packet: respPkt})

		data, err := pkt.Encode()
		require.NoError(t, err)

		_, err = clientConn.Write(data)
		require.NoError(t, err)

		buffer := make([]byte, 4096)
		clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		_, err = clientConn.Read(buffer)
		assert.Error(t, err, "Should reject packet with invalid Message-Authenticator")
	})
}

func TestServerGracefulShutdown(t *testing.T) {
	// TDD: Server should wait for in-flight requests to complete before Close() returns
	dict := dictionary.New()
	require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

	// Create a handler that takes some time to process
	processingStarted := make(chan struct{})
	processingDone := make(chan struct{})

	slowHandler := HandlerFunc(func(req *Request) (Response, error) {
		close(processingStarted)
		time.Sleep(200 * time.Millisecond) // Simulate slow processing
		close(processingDone)
		respPkt := packet.New(packet.CodeAccessAccept, req.packet.Identifier)
		return Response{packet: respPkt}, nil
	})

	secret := []byte("testing123")
	combinedHandler := &combinedTestHandler{
		secretResp:    SecretResponse{Secret: secret},
		radiusHandler: slowHandler,
	}

	srv, err := New(Config{
		Handler:    combinedHandler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	startTestServer(t, srv)

	serverAddr := srv.Addr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	// Send a request
	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
	pkt.AddMessageAuthenticator(secret, pkt.Authenticator)
	data, _ := pkt.Encode()
	_, err = clientConn.Write(data)
	require.NoError(t, err)

	// Wait for processing to start
	select {
	case <-processingStarted:
		// Good, handler started processing
	case <-time.After(1 * time.Second):
		t.Fatal("Handler never started processing")
	}

	// Close server while request is being processed
	closeComplete := make(chan struct{})
	go func() {
		srv.Close()
		close(closeComplete)
	}()

	// Verify handler completes
	select {
	case <-processingDone:
		// Good, handler finished
	case <-time.After(1 * time.Second):
		t.Fatal("Handler never completed")
	}

	// Close should complete shortly after handler finishes
	select {
	case <-closeComplete:
		// Good, close completed
	case <-time.After(500 * time.Millisecond):
		t.Fatal("Server Close() didn't complete after handler finished")
	}
}

func TestServerShutdownWaitsForAllRequests(t *testing.T) {
	// TDD: Multiple concurrent requests should all complete before shutdown
	dict := dictionary.New()
	require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

	var processedCount int32
	var mu sync.Mutex

	slowHandler := HandlerFunc(func(req *Request) (Response, error) {
		time.Sleep(100 * time.Millisecond)
		mu.Lock()
		processedCount++
		mu.Unlock()
		respPkt := packet.New(packet.CodeAccessAccept, req.packet.Identifier)
		return Response{packet: respPkt}, nil
	})

	secret := []byte("testing123")
	combinedHandler := &combinedTestHandler{
		secretResp:    SecretResponse{Secret: secret},
		radiusHandler: slowHandler,
	}

	srv, err := New(Config{
		Handler:    combinedHandler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	startTestServer(t, srv)

	serverAddr := srv.Addr().(*net.UDPAddr)

	// Send multiple concurrent requests
	numRequests := 5
	var wg sync.WaitGroup
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			conn, err := net.DialUDP("udp", nil, serverAddr)
			if err != nil {
				return
			}
			defer conn.Close()

			pkt := packet.New(packet.CodeAccessRequest, uint8(id))
			pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
			pkt.AddMessageAuthenticator(secret, pkt.Authenticator)
			data, _ := pkt.Encode()
			conn.Write(data)

			buffer := make([]byte, 4096)
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			conn.Read(buffer)
		}(i)
	}

	// Give requests time to start processing
	time.Sleep(50 * time.Millisecond)

	// Close server
	srv.Close()

	// Wait for all client goroutines
	wg.Wait()

	// All requests that started should have been processed
	mu.Lock()
	count := processedCount
	mu.Unlock()
	assert.GreaterOrEqual(t, int(count), 1, "At least some requests should have been processed")
}

func TestServerRequestTimeout(t *testing.T) {
	// TDD: Request context should have configurable timeout
	dict := dictionary.New()
	require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

	var ctxTimeout time.Duration
	var ctxHadDeadline bool
	var mu sync.Mutex

	handler := HandlerFunc(func(req *Request) (Response, error) {
		// Check if context has deadline
		deadline, ok := req.Context.Deadline()
		mu.Lock()
		ctxHadDeadline = ok
		if ok {
			ctxTimeout = time.Until(deadline)
		}
		mu.Unlock()
		respPkt := packet.New(packet.CodeAccessAccept, req.packet.Identifier)
		return Response{packet: respPkt}, nil
	})

	secret := []byte("testing123")
	combinedHandler := &combinedTestHandler{
		secretResp:    SecretResponse{Secret: secret},
		radiusHandler: handler,
	}

	timeout := 5 * time.Second
	srv, err := New(Config{
		Handler:        combinedHandler,
		Dictionary:     dict,
		RequestTimeout: &timeout,
	})
	require.NoError(t, err)
	defer srv.Close()

	startTestServer(t, srv)

	serverAddr := srv.Addr().(*net.UDPAddr)
	clientConn, err := net.DialUDP("udp", nil, serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewAttribute(1, []byte("testuser")))
	pkt.AddMessageAuthenticator(secret, pkt.Authenticator)
	data, _ := pkt.Encode()
	clientConn.Write(data)

	buffer := make([]byte, 4096)
	clientConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	clientConn.Read(buffer)

	// Context should have had a deadline
	mu.Lock()
	hadDeadline := ctxHadDeadline
	timeoutValue := ctxTimeout
	mu.Unlock()

	assert.True(t, hadDeadline, "Request context should have deadline when RequestTimeout is set")
	if hadDeadline {
		assert.InDelta(t, timeout.Seconds(), timeoutValue.Seconds(), 1.0, "Context timeout should match configured value")
	}
}

// Tests for Server.Serve with external transport

func TestServerServeWithUDPTransport(t *testing.T) {
	secret := []byte("testing123")
	dict, _ := dictionaries.NewDefault()

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 1)},
	}

	srv, err := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	// Create external UDP connection
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	transport := NewUDPTransport(conn)

	// Start server with external transport
	go srv.Serve(transport)
	defer srv.Close()

	// Wait for server to be ready
	time.Sleep(50 * time.Millisecond)

	// Send request
	clientConn, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer clientConn.Close()

	reqPkt := packet.New(packet.CodeAccessRequest, 1)
	reqPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
	data, _ := reqPkt.Encode()

	_, err = clientConn.Write(data)
	require.NoError(t, err)

	// Read response
	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	require.NoError(t, err)

	respPkt, err := packet.Decode(buf[:n])
	require.NoError(t, err)
	assert.Equal(t, packet.CodeAccessAccept, respPkt.Code)
}

func TestServerServeWithTCPTransport(t *testing.T) {
	secret := []byte("testing123")
	dict, _ := dictionaries.NewDefault()

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 1)},
	}

	srv, err := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	// Create external TCP listener
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	// Start server with external transport
	go srv.Serve(transport)
	defer srv.Close()

	// Wait for server to be ready
	time.Sleep(50 * time.Millisecond)

	// Connect via TCP
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Send RADIUS packet
	reqPkt := packet.New(packet.CodeAccessRequest, 1)
	reqPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
	data, _ := reqPkt.Encode()

	_, err = conn.Write(data)
	require.NoError(t, err)

	// Read response
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)

	respPkt, err := packet.Decode(buf[:n])
	require.NoError(t, err)
	assert.Equal(t, packet.CodeAccessAccept, respPkt.Code)
}

func TestServerServeWithTCPTransportMultiplePackets(t *testing.T) {
	secret := []byte("testing123")
	dict, _ := dictionaries.NewDefault()

	var counter int
	var mu sync.Mutex

	handler := HandlerFunc(func(r *Request) (Response, error) {
		mu.Lock()
		counter++
		mu.Unlock()
		resp := NewResponse(r)
		resp.SetCode(packet.CodeAccessAccept)
		return resp, nil
	})

	combinedHandler := &combinedTestHandler{
		secretResp:    SecretResponse{Secret: secret},
		radiusHandler: handler,
	}

	srv, err := New(Config{
		Handler:    combinedHandler,
		Dictionary: dict,
	})
	require.NoError(t, err)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)
	go srv.Serve(transport)
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	// Send multiple packets on same connection
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	numPackets := 5
	for i := range numPackets {
		reqPkt := packet.New(packet.CodeAccessRequest, byte(i+1))
		reqPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		data, _ := reqPkt.Encode()

		_, err = conn.Write(data)
		require.NoError(t, err)

		// Read response
		conn.SetReadDeadline(time.Now().Add(time.Second))
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		require.NoError(t, err)

		respPkt, err := packet.Decode(buf[:n])
		require.NoError(t, err)
		assert.Equal(t, packet.CodeAccessAccept, respPkt.Code)
		assert.Equal(t, byte(i+1), respPkt.Identifier)
	}

	mu.Lock()
	assert.Equal(t, numPackets, counter)
	mu.Unlock()
}

// Tests for Request accessor methods

func TestRequestGetAttribute(t *testing.T) {
	dict, _ := dictionaries.NewDefault()
	pkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	_ = pkt.AddAttributeByName("User-Name", "testuser")
	_ = pkt.AddAttributeByName("NAS-IP-Address", "192.168.1.1")

	req := &Request{packet: pkt}

	t.Run("existing attribute", func(t *testing.T) {
		values := req.GetAttribute("User-Name")
		require.Len(t, values, 1)
		assert.Equal(t, "testuser", values[0].String())
	})

	t.Run("non-existing attribute", func(t *testing.T) {
		values := req.GetAttribute("Called-Station-Id")
		assert.Empty(t, values)
	})

	t.Run("nil packet", func(t *testing.T) {
		nilReq := &Request{}
		values := nilReq.GetAttribute("User-Name")
		assert.Empty(t, values)
	})
}

func TestRequestListAttributes(t *testing.T) {
	dict, _ := dictionaries.NewDefault()
	pkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	_ = pkt.AddAttributeByName("User-Name", "testuser")
	_ = pkt.AddAttributeByName("NAS-IP-Address", "192.168.1.1")

	req := &Request{packet: pkt}

	t.Run("list attributes", func(t *testing.T) {
		attrs := req.ListAttributes()
		assert.Len(t, attrs, 2)
		assert.Contains(t, attrs, "User-Name")
		assert.Contains(t, attrs, "NAS-IP-Address")
	})

	t.Run("nil packet", func(t *testing.T) {
		nilReq := &Request{}
		attrs := nilReq.ListAttributes()
		assert.Empty(t, attrs)
	})
}

func TestRequestCode(t *testing.T) {
	pkt := packet.New(packet.CodeAccessRequest, 1)
	req := &Request{packet: pkt}

	t.Run("access request", func(t *testing.T) {
		assert.Equal(t, packet.CodeAccessRequest, req.Code())
	})

	t.Run("nil packet", func(t *testing.T) {
		nilReq := &Request{}
		assert.Equal(t, packet.Code(0), nilReq.Code())
	})
}

func TestResponseCode(t *testing.T) {
	pkt := packet.New(packet.CodeAccessAccept, 1)
	resp := Response{packet: pkt}

	t.Run("access accept", func(t *testing.T) {
		assert.Equal(t, packet.CodeAccessAccept, resp.Code())
	})

	t.Run("nil packet", func(t *testing.T) {
		nilResp := Response{}
		assert.Equal(t, packet.Code(0), nilResp.Code())
	})
}

func TestResponseListAttributes(t *testing.T) {
	dict, _ := dictionaries.NewDefault()
	pkt := packet.NewWithDictionary(packet.CodeAccessAccept, 1, dict)
	_ = pkt.AddAttributeByName("Session-Timeout", uint32(3600))
	_ = pkt.AddAttributeByName("Framed-IP-Address", "10.0.0.1")

	resp := Response{packet: pkt}

	t.Run("list attributes", func(t *testing.T) {
		attrs := resp.ListAttributes()
		assert.Len(t, attrs, 2)
		assert.Contains(t, attrs, "Session-Timeout")
		assert.Contains(t, attrs, "Framed-IP-Address")
	})

	t.Run("nil packet", func(t *testing.T) {
		nilResp := Response{}
		attrs := nilResp.ListAttributes()
		assert.Empty(t, attrs)
	})
}

// Tests for HandlerFunc

func TestHandlerFuncServeSecret(t *testing.T) {
	handler := HandlerFunc(func(r *Request) (Response, error) {
		return NewResponse(r), nil
	})

	resp, err := handler.ServeSecret(SecretRequest{})
	require.NoError(t, err)
	assert.Empty(t, resp.Secret)
	assert.Nil(t, resp.Metadata)
}

func TestHandlerFuncServeRADIUS(t *testing.T) {
	dict, _ := dictionaries.NewDefault()
	pkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)

	called := false
	handler := HandlerFunc(func(r *Request) (Response, error) {
		called = true
		resp := NewResponse(r)
		resp.SetCode(packet.CodeAccessAccept)
		return resp, nil
	})

	req := &Request{packet: pkt}
	resp, err := handler.ServeRADIUS(req)
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, packet.CodeAccessAccept, resp.Code())
}

// Test for Server.Addr before ready

func TestServerAddrBeforeReady(t *testing.T) {
	srv, _ := New(Config{
	})

	// Start getting address in goroutine (will block until ready)
	addrChan := make(chan net.Addr, 1)
	go func() {
		addrChan <- srv.Addr()
	}()

	// Should not return immediately
	select {
	case <-addrChan:
		t.Fatal("Addr() returned before server was ready")
	case <-time.After(50 * time.Millisecond):
		// Expected
	}

	// Start server
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	transport := NewUDPTransport(conn)
	go srv.Serve(transport)
	defer srv.Close()

	// Now should return
	select {
	case addr := <-addrChan:
		assert.NotNil(t, addr)
	case <-time.After(time.Second):
		t.Fatal("Addr() did not return after server started")
	}
}

func BenchmarkServerThroughput(b *testing.B) {
	secret := []byte("testing123")
	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 0)},
	}

	srv, _ := New(Config{
		Handler: handler,
	})

	startTestServer(b, srv)
	defer srv.Close()

	addr := srv.Addr().(*net.UDPAddr)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		conn, _ := net.DialUDP("udp", nil, addr)
		defer conn.Close()

		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.AddMessageAuthenticator(secret, pkt.Authenticator)
		data, _ := pkt.Encode()

		buffer := make([]byte, 4096)

		for pb.Next() {
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Write(data)
			conn.Read(buffer)
		}
	})
}

// Server performance benchmarks with different transports

func BenchmarkServerWithUDPTransport(b *testing.B) {
	secret := []byte("testing123")
	dict, _ := dictionaries.NewDefault()

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 1)},
	}

	srv, _ := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	transport := NewUDPTransport(conn)

	go srv.Serve(transport)
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	reqPkt := packet.New(packet.CodeAccessRequest, 1)
	reqPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
	data, _ := reqPkt.Encode()

	b.SetBytes(int64(len(data) * 2))
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		clientConn, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
		defer clientConn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			clientConn.SetDeadline(time.Now().Add(time.Second))
			clientConn.Write(data)
			clientConn.Read(buf)
		}
	})
}

func BenchmarkServerWithTCPTransport(b *testing.B) {
	secret := []byte("testing123")
	dict, _ := dictionaries.NewDefault()

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 1)},
	}

	srv, _ := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	transport := NewTCPTransport(listener)

	go srv.Serve(transport)
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	reqPkt := packet.New(packet.CodeAccessRequest, 1)
	reqPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
	data, _ := reqPkt.Encode()

	b.SetBytes(int64(len(data) * 2))
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		conn, _ := net.Dial("tcp", listener.Addr().String())
		defer conn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			conn.SetDeadline(time.Now().Add(time.Second))
			conn.Write(data)
			conn.Read(buf)
		}
	})
}

func BenchmarkServerWithTCPTransport_StreamMode(b *testing.B) {
	secret := []byte("testing123")
	dict, _ := dictionaries.NewDefault()

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 1)},
	}

	srv, _ := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})

	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	transport := NewTCPTransport(listener)

	go srv.Serve(transport)
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	reqPkt := packet.New(packet.CodeAccessRequest, 1)
	reqPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
	data, _ := reqPkt.Encode()

	b.SetBytes(int64(len(data) * 2))
	b.ResetTimer()
	b.ReportAllocs()

	// Each goroutine gets its own connection
	b.RunParallel(func(pb *testing.PB) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			conn.SetDeadline(time.Now().Add(time.Second))
			conn.Write(data)
			conn.Read(buf)
		}
	})
}

func BenchmarkServerHandlePacketWithMiddleware(b *testing.B) {
	dict, _ := dictionaries.NewDefault()
	secret := []byte("testing123")

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
		radiusResp: Response{packet: packet.New(packet.CodeAccessAccept, 1)},
	}

	srv, _ := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})

	// Add middlewares
	for range 3 {
		srv.Use(func(next Handler) Handler {
			return HandlerFunc(func(r *Request) (Response, error) {
				return next.ServeRADIUS(r)
			})
		})
	}

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	transport := NewUDPTransport(conn)

	go srv.Serve(transport)
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	reqPkt := packet.New(packet.CodeAccessRequest, 1)
	reqPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
	data, _ := reqPkt.Encode()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		clientConn, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
		defer clientConn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			clientConn.SetDeadline(time.Now().Add(time.Second))
			clientConn.Write(data)
			clientConn.Read(buf)
		}
	})
}

func BenchmarkServerWithRealisticPacket(b *testing.B) {
	dict, _ := dictionaries.NewDefault()
	secret := []byte("testing123")

	handler := &testHandler{
		secretResp: SecretResponse{Secret: secret},
	}

	// Create realistic response with multiple attributes
	respPkt := packet.NewWithDictionary(packet.CodeAccessAccept, 1, dict)
	_ = respPkt.AddAttributeByName("Session-Timeout", uint32(3600))
	_ = respPkt.AddAttributeByName("Idle-Timeout", uint32(600))
	_ = respPkt.AddAttributeByName("Framed-IP-Address", "10.0.0.1")
	_ = respPkt.AddAttributeByName("Framed-IP-Netmask", "255.255.255.0")
	handler.radiusResp = Response{packet: respPkt}

	srv, _ := New(Config{
		Handler:    handler,
		Dictionary: dict,
	})

	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	transport := NewUDPTransport(conn)

	go srv.Serve(transport)
	defer srv.Close()

	time.Sleep(50 * time.Millisecond)

	// Create realistic request with multiple attributes
	reqPkt := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)
	_ = reqPkt.AddAttributeByName("User-Name", "testuser@example.com")
	_ = reqPkt.AddAttributeByName("User-Password", "secretpassword123")
	_ = reqPkt.AddAttributeByName("NAS-IP-Address", "192.168.1.1")
	_ = reqPkt.AddAttributeByName("NAS-Port", uint32(12345))
	_ = reqPkt.AddAttributeByName("Called-Station-Id", "00-11-22-33-44-55")
	_ = reqPkt.AddAttributeByName("Calling-Station-Id", "AA-BB-CC-DD-EE-FF")
	reqAuth := reqPkt.CalculateRequestAuthenticator(secret)
	reqPkt.SetAuthenticator(reqAuth)
	reqPkt.AddMessageAuthenticator(secret, reqAuth)
	data, _ := reqPkt.Encode()

	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		clientConn, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
		defer clientConn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			clientConn.SetDeadline(time.Now().Add(time.Second))
			clientConn.Write(data)
			clientConn.Read(buf)
		}
	})
}
