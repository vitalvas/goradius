package goradius

import (
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestRADIUSPacket creates a minimal valid RADIUS packet for testing.
// Code 1 (Access-Request), random identifier, specified length.
func createTestRADIUSPacket(payloadSize int) []byte {
	length := uint16(20 + payloadSize) // header + payload
	pkt := make([]byte, length)
	pkt[0] = 1 // Code: Access-Request
	pkt[1] = 1 // Identifier
	binary.BigEndian.PutUint16(pkt[2:4], length)
	// Authenticator (16 bytes) is zeroed
	// Optional payload follows
	return pkt
}

func TestUDPTransport_Serve(t *testing.T) {
	// Create UDP connection
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	transport := NewUDPTransport(conn)
	require.NotNil(t, transport)

	// Track received packets
	var receivedData []byte
	var receivedAddr net.Addr
	var respondCalled atomic.Bool
	handlerDone := make(chan struct{})

	handler := func(data []byte, remoteAddr net.Addr, respond ResponderFunc) {
		receivedData = data
		receivedAddr = remoteAddr
		respondCalled.Store(true)
		// Send response
		err := respond([]byte("response"))
		assert.NoError(t, err)
		close(handlerDone)
	}

	// Start serving in goroutine
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- transport.Serve(handler)
	}()

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Send packet to server
	clientConn, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer clientConn.Close()

	testData := []byte("test packet")
	_, err = clientConn.Write(testData)
	require.NoError(t, err)

	// Wait for handler
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler not called")
	}

	// Verify received data
	assert.Equal(t, testData, receivedData)
	assert.NotNil(t, receivedAddr)
	assert.True(t, respondCalled.Load())

	// Read response
	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, []byte("response"), buf[:n])

	// Close transport
	err = transport.Close()
	require.NoError(t, err)
}

func TestUDPTransport_LocalAddr(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer conn.Close()

	transport := NewUDPTransport(conn)
	addr := transport.LocalAddr()

	require.NotNil(t, addr)
	assert.Equal(t, "udp", addr.Network())
	assert.Contains(t, addr.String(), "127.0.0.1")
}

func TestUDPTransport_Close(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	transport := NewUDPTransport(conn)

	// Start serving
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- transport.Serve(func(_ []byte, _ net.Addr, _ ResponderFunc) {})
	}()

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Close should work
	err = transport.Close()
	require.NoError(t, err)

	// Serve should return
	select {
	case err := <-serveErr:
		// Expected - connection closed error or nil
		_ = err
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Close")
	}

	// Double close should be safe
	err = transport.Close()
	require.NoError(t, err)
}

func TestUDPTransport_GracefulShutdown(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	transport := NewUDPTransport(conn)

	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})

	handler := func(_ []byte, _ net.Addr, _ ResponderFunc) {
		close(handlerStarted)
		time.Sleep(100 * time.Millisecond) // Simulate slow handler
		close(handlerDone)
	}

	// Start serving
	go transport.Serve(handler)

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Send packet
	clientConn, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer clientConn.Close()

	_, err = clientConn.Write([]byte("test"))
	require.NoError(t, err)

	// Wait for handler to start
	<-handlerStarted

	// Close transport - should wait for handler
	closeDone := make(chan struct{})
	go func() {
		transport.Close()
		close(closeDone)
	}()

	// Handler should complete before Close returns
	select {
	case <-handlerDone:
	case <-closeDone:
		t.Fatal("Close returned before handler completed")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler")
	}

	// Now Close should return
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after handler completed")
	}
}

func TestUDPTransport_ConcurrentPackets(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	transport := NewUDPTransport(conn)

	var counter atomic.Int32
	var wg sync.WaitGroup

	handler := func(_ []byte, _ net.Addr, _ ResponderFunc) {
		counter.Add(1)
		wg.Done()
	}

	// Start serving
	go transport.Serve(handler)

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Send multiple packets concurrently
	numPackets := 100
	wg.Add(numPackets)

	for range numPackets {
		go func() {
			clientConn, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
			if err != nil {
				return
			}
			defer clientConn.Close()
			clientConn.Write([]byte("test"))
		}()
	}

	// Wait for all handlers with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("only received %d/%d packets", counter.Load(), numPackets)
	}

	transport.Close()
	assert.Equal(t, int32(numPackets), counter.Load())
}

// TCP Transport Tests

func TestTCPTransport_Serve(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)
	require.NotNil(t, transport)

	// Track received packets
	var receivedData []byte
	var receivedAddr net.Addr
	var respondCalled atomic.Bool
	handlerDone := make(chan struct{})

	handler := func(data []byte, remoteAddr net.Addr, respond ResponderFunc) {
		receivedData = make([]byte, len(data))
		copy(receivedData, data)
		receivedAddr = remoteAddr
		respondCalled.Store(true)
		// Send response (a minimal RADIUS packet)
		resp := createTestRADIUSPacket(0)
		resp[0] = 2 // Access-Accept
		err := respond(resp)
		assert.NoError(t, err)
		close(handlerDone)
	}

	// Start serving
	go transport.Serve(handler)

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Connect to server
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Send RADIUS packet with proper framing
	testPacket := createTestRADIUSPacket(10)
	_, err = conn.Write(testPacket)
	require.NoError(t, err)

	// Wait for handler
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler not called")
	}

	// Verify received data
	assert.Equal(t, testPacket, receivedData)
	assert.NotNil(t, receivedAddr)
	assert.True(t, respondCalled.Load())

	// Read response
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, 20, n)           // Minimal RADIUS packet
	assert.Equal(t, byte(2), buf[0]) // Access-Accept

	// Close transport
	err = transport.Close()
	require.NoError(t, err)
}

func TestTCPTransport_MultiplePacketsPerConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	var counter atomic.Int32
	var wg sync.WaitGroup
	numPackets := 5
	wg.Add(numPackets)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		counter.Add(1)
		// Send response
		resp := createTestRADIUSPacket(0)
		respond(resp)
		wg.Done()
	}

	// Start serving
	go transport.Serve(handler)

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Connect to server
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Send multiple packets on same connection
	for i := range numPackets {
		pkt := createTestRADIUSPacket(0)
		pkt[1] = byte(i) // Different identifier for each
		_, err = conn.Write(pkt)
		require.NoError(t, err)
	}

	// Wait for all handlers
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatalf("only received %d/%d packets", counter.Load(), numPackets)
	}

	assert.Equal(t, int32(numPackets), counter.Load())

	transport.Close()
}

func TestTCPTransport_LocalAddr(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	transport := NewTCPTransport(listener)
	addr := transport.LocalAddr()

	require.NotNil(t, addr)
	assert.Equal(t, "tcp", addr.Network())
	assert.Contains(t, addr.String(), "127.0.0.1")
}

func TestTCPTransport_Close(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	// Start serving
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- transport.Serve(func(_ []byte, _ net.Addr, _ ResponderFunc) {})
	}()

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Close should work
	err = transport.Close()
	require.NoError(t, err)

	// Serve should return
	select {
	case err := <-serveErr:
		_ = err // Expected - listener closed error or nil
	case <-time.After(time.Second):
		t.Fatal("Serve did not return after Close")
	}

	// Double close should be safe
	err = transport.Close()
	require.NoError(t, err)
}

func TestTCPTransport_GracefulShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})

	handler := func(_ []byte, _ net.Addr, _ ResponderFunc) {
		close(handlerStarted)
		time.Sleep(100 * time.Millisecond) // Simulate slow handler
		close(handlerDone)
	}

	// Start serving
	go transport.Serve(handler)

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Connect and send packet
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	pkt := createTestRADIUSPacket(0)
	_, err = conn.Write(pkt)
	require.NoError(t, err)

	// Wait for handler to start
	<-handlerStarted

	// Close transport - should wait for handler
	closeDone := make(chan struct{})
	go func() {
		transport.Close()
		close(closeDone)
	}()

	// Handler should complete before Close returns
	select {
	case <-handlerDone:
	case <-closeDone:
		t.Fatal("Close returned before handler completed")
	case <-time.After(time.Second):
		t.Fatal("timeout waiting for handler")
	}

	// Now Close should return
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("Close did not return after handler completed")
	}
}

func TestTCPTransport_MultipleConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	var counter atomic.Int32
	var wg sync.WaitGroup
	numConns := 10
	wg.Add(numConns)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		counter.Add(1)
		resp := createTestRADIUSPacket(0)
		respond(resp)
		wg.Done()
	}

	// Start serving
	go transport.Serve(handler)

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	// Create multiple connections concurrently
	for range numConns {
		go func() {
			conn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				return
			}
			defer conn.Close()

			pkt := createTestRADIUSPacket(0)
			conn.Write(pkt)

			// Read response
			buf := make([]byte, 1024)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.Read(buf)
		}()
	}

	// Wait for all handlers
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("only received %d/%d connections", counter.Load(), numConns)
	}

	transport.Close()
	assert.Equal(t, int32(numConns), counter.Load())
}

func TestTCPTransport_InvalidPacketLength(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	handlerCalled := make(chan struct{}, 1)
	handler := func(_ []byte, _ net.Addr, _ ResponderFunc) {
		handlerCalled <- struct{}{}
	}

	// Start serving
	go transport.Serve(handler)

	// Wait for server to start
	time.Sleep(10 * time.Millisecond)

	t.Run("packet too small", func(t *testing.T) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		// Send packet with length < 20
		pkt := make([]byte, 4)
		pkt[0] = 1                               // Code
		pkt[1] = 1                               // ID
		binary.BigEndian.PutUint16(pkt[2:4], 10) // Length = 10 (invalid, too small)
		conn.Write(pkt)

		// Handler should not be called
		select {
		case <-handlerCalled:
			t.Fatal("handler was called for invalid packet")
		case <-time.After(100 * time.Millisecond):
			// Expected - invalid packet rejected
		}
	})

	t.Run("packet too large", func(t *testing.T) {
		conn, err := net.Dial("tcp", listener.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		// Send packet with length > 4096
		pkt := make([]byte, 4)
		pkt[0] = 1                                 // Code
		pkt[1] = 1                                 // ID
		binary.BigEndian.PutUint16(pkt[2:4], 5000) // Length = 5000 (invalid, too large)
		conn.Write(pkt)

		// Handler should not be called
		select {
		case <-handlerCalled:
			t.Fatal("handler was called for invalid packet")
		case <-time.After(100 * time.Millisecond):
			// Expected - invalid packet rejected
		}
	})

	transport.Close()
}

func TestTCPTransport_PartialPacketRead(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	var receivedData []byte
	handlerDone := make(chan struct{})
	handler := func(data []byte, _ net.Addr, respond ResponderFunc) {
		receivedData = make([]byte, len(data))
		copy(receivedData, data)
		respond(createTestRADIUSPacket(0))
		close(handlerDone)
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	// Connect and send packet in parts
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Create a larger packet with attributes
	pkt := createTestRADIUSPacket(50)

	// Send header first
	_, err = conn.Write(pkt[:10])
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	// Send rest of packet
	_, err = conn.Write(pkt[10:])
	require.NoError(t, err)

	// Wait for handler
	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler not called")
	}

	assert.Equal(t, pkt, receivedData)
}

func TestTCPTransport_ConnectionClosedDuringRead(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	handlerCalled := make(chan struct{}, 1)
	handler := func(_ []byte, _ net.Addr, _ ResponderFunc) {
		handlerCalled <- struct{}{}
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	// Connect and send partial header, then close
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	// Send only 10 bytes (less than header)
	partial := make([]byte, 10)
	partial[0] = 1
	partial[1] = 1
	binary.BigEndian.PutUint16(partial[2:4], 30) // Expect 30 bytes total
	conn.Write(partial)

	// Close connection without sending rest
	conn.Close()

	// Handler should not be called
	select {
	case <-handlerCalled:
		t.Fatal("handler was called for incomplete packet")
	case <-time.After(100 * time.Millisecond):
		// Expected
	}
}

func TestTCPTransport_LargeValidPacket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	var receivedLen int
	handlerDone := make(chan struct{})
	handler := func(data []byte, _ net.Addr, respond ResponderFunc) {
		receivedLen = len(data)
		respond(createTestRADIUSPacket(0))
		close(handlerDone)
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer conn.Close()

	// Create a large valid packet (near max size)
	pkt := createTestRADIUSPacket(4000) // Total: 4020 bytes

	_, err = conn.Write(pkt)
	require.NoError(t, err)

	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler not called")
	}

	assert.Equal(t, 4020, receivedLen)
}

func TestUDPTransport_TimeoutError(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	// Set a short deadline to trigger timeout
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))

	transport := NewUDPTransport(conn)

	handlerCalled := make(chan struct{}, 1)
	handler := func(_ []byte, _ net.Addr, _ ResponderFunc) {
		handlerCalled <- struct{}{}
	}

	// Start serving - should handle timeout gracefully
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- transport.Serve(handler)
	}()

	// Wait for timeout to occur
	time.Sleep(100 * time.Millisecond)

	// Send a packet after timeout - should still work
	clientConn, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer clientConn.Close()

	clientConn.Write([]byte("test"))

	// Handler may or may not be called depending on timing
	// Just verify server didn't crash
	transport.Close()

	select {
	case err := <-serveErr:
		assert.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("Serve did not return")
	}
}

// Benchmarks for transports

func BenchmarkUDPTransport_Serve(b *testing.B) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	transport := NewUDPTransport(conn)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	clientConn, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	defer clientConn.Close()

	pkt := createTestRADIUSPacket(0)
	buf := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		clientConn.Write(pkt)
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		clientConn.Read(buf)
	}
}

func BenchmarkTCPTransport_Serve(b *testing.B) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	transport := NewTCPTransport(listener)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	conn, _ := net.Dial("tcp", listener.Addr().String())
	defer conn.Close()

	pkt := createTestRADIUSPacket(0)
	buf := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		conn.Write(pkt)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		conn.Read(buf)
	}
}

func BenchmarkTCPTransport_MultipleConnections(b *testing.B) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	transport := NewTCPTransport(listener)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	pkt := createTestRADIUSPacket(0)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		conn, _ := net.Dial("tcp", listener.Addr().String())
		defer conn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			conn.Write(pkt)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.Read(buf)
		}
	})
}

// Performance benchmarks with various packet sizes

func BenchmarkUDPTransport_SmallPacket(b *testing.B) {
	benchmarkUDPTransportWithSize(b, 0) // 20 bytes (header only)
}

func BenchmarkUDPTransport_MediumPacket(b *testing.B) {
	benchmarkUDPTransportWithSize(b, 100) // 120 bytes
}

func BenchmarkUDPTransport_LargePacket(b *testing.B) {
	benchmarkUDPTransportWithSize(b, 1000) // 1020 bytes
}

func BenchmarkUDPTransport_MaxPacket(b *testing.B) {
	benchmarkUDPTransportWithSize(b, 4076) // 4096 bytes (max)
}

func benchmarkUDPTransportWithSize(b *testing.B, payloadSize int) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	transport := NewUDPTransport(conn)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	clientConn, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	defer clientConn.Close()

	pkt := createTestRADIUSPacket(payloadSize)
	buf := make([]byte, 4096)

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		clientConn.Write(pkt)
		clientConn.SetReadDeadline(time.Now().Add(time.Second))
		clientConn.Read(buf)
	}
}

func BenchmarkTCPTransport_SmallPacket(b *testing.B) {
	benchmarkTCPTransportWithSize(b, 0) // 20 bytes
}

func BenchmarkTCPTransport_MediumPacket(b *testing.B) {
	benchmarkTCPTransportWithSize(b, 100) // 120 bytes
}

func BenchmarkTCPTransport_LargePacket(b *testing.B) {
	benchmarkTCPTransportWithSize(b, 1000) // 1020 bytes
}

func BenchmarkTCPTransport_MaxPacket(b *testing.B) {
	benchmarkTCPTransportWithSize(b, 4076) // 4096 bytes (max)
}

func benchmarkTCPTransportWithSize(b *testing.B, payloadSize int) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	transport := NewTCPTransport(listener)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	conn, _ := net.Dial("tcp", listener.Addr().String())
	defer conn.Close()

	pkt := createTestRADIUSPacket(payloadSize)
	buf := make([]byte, 4096)

	b.SetBytes(int64(len(pkt)))
	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		conn.Write(pkt)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		conn.Read(buf)
	}
}

// Throughput benchmarks

func BenchmarkUDPTransport_Throughput(b *testing.B) {
	conn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	transport := NewUDPTransport(conn)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	pkt := createTestRADIUSPacket(50) // Realistic packet size

	b.SetBytes(int64(len(pkt) * 2)) // Request + Response
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		clientConn, _ := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
		defer clientConn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			clientConn.Write(pkt)
			clientConn.SetReadDeadline(time.Now().Add(time.Second))
			clientConn.Read(buf)
		}
	})
}

func BenchmarkTCPTransport_Throughput(b *testing.B) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	transport := NewTCPTransport(listener)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	pkt := createTestRADIUSPacket(50) // Realistic packet size

	b.SetBytes(int64(len(pkt) * 2)) // Request + Response
	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		conn, _ := net.Dial("tcp", listener.Addr().String())
		defer conn.Close()
		buf := make([]byte, 4096)

		for pb.Next() {
			conn.Write(pkt)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.Read(buf)
		}
	})
}

// Connection establishment benchmarks

func BenchmarkTCPTransport_NewConnection(b *testing.B) {
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	transport := NewTCPTransport(listener)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	time.Sleep(10 * time.Millisecond)

	addr := listener.Addr().String()
	pkt := createTestRADIUSPacket(0)
	buf := make([]byte, 4096)

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			continue
		}
		conn.Write(pkt)
		conn.SetReadDeadline(time.Now().Add(time.Second))
		conn.Read(buf)
		conn.Close()
	}
}

// Handler processing benchmark (no network overhead)

func BenchmarkTransportHandler_Processing(b *testing.B) {
	var processed int64

	handler := func(data []byte, _ net.Addr, respond ResponderFunc) {
		processed += int64(len(data))
		respond(createTestRADIUSPacket(0))
	}

	pkt := createTestRADIUSPacket(50)
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
	respond := func(_ []byte) error { return nil }

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		handler(pkt, addr, respond)
	}

	b.SetBytes(processed / int64(b.N))
}

// Concurrent connections benchmark

func BenchmarkTCPTransport_ConcurrentConnections_10(b *testing.B) {
	benchmarkTCPConcurrentConnections(b, 10)
}

func BenchmarkTCPTransport_ConcurrentConnections_50(b *testing.B) {
	benchmarkTCPConcurrentConnections(b, 50)
}

func BenchmarkTCPTransport_ConcurrentConnections_100(b *testing.B) {
	benchmarkTCPConcurrentConnections(b, 100)
}

func benchmarkTCPConcurrentConnections(b *testing.B, numConns int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("failed to create listener: %v", err)
	}
	transport := NewTCPTransport(listener)

	handler := func(_ []byte, _ net.Addr, respond ResponderFunc) {
		respond(createTestRADIUSPacket(0))
	}

	go transport.Serve(handler)
	defer transport.Close()

	// Wait for listener to be ready
	time.Sleep(50 * time.Millisecond)

	// Pre-establish connections with retries
	addr := listener.Addr().String()
	conns := make([]net.Conn, 0, numConns)
	for range numConns {
		var conn net.Conn
		for range 3 {
			conn, err = net.Dial("tcp", addr)
			if err == nil {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if conn != nil {
			conns = append(conns, conn)
		}
	}
	if len(conns) == 0 {
		b.Skipf("could not establish connections to %s", addr)
	}
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
	}()

	pkt := createTestRADIUSPacket(0)

	b.ResetTimer()
	b.ReportAllocs()

	numEstablished := len(conns)
	b.RunParallel(func(pb *testing.PB) {
		// Each goroutine picks a connection
		connIdx := 0
		buf := make([]byte, 4096)

		for pb.Next() {
			conn := conns[connIdx%numEstablished]
			connIdx++

			conn.Write(pkt)
			conn.SetReadDeadline(time.Now().Add(time.Second))
			conn.Read(buf)
		}
	})
}
