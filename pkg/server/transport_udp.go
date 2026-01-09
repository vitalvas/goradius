package server

import (
	"net"
	"sync"
)

// udpBufferPool provides reusable buffers for UDP packet reads
var udpBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

// UDPTransport implements Transport for UDP connections.
type UDPTransport struct {
	conn   net.PacketConn
	wg     sync.WaitGroup
	mu     sync.RWMutex
	closed bool
}

// NewUDPTransport creates a UDP transport from an existing PacketConn.
// The caller is responsible for creating the connection.
func NewUDPTransport(conn net.PacketConn) *UDPTransport {
	return &UDPTransport{
		conn: conn,
	}
}

// Serve implements Transport.Serve for UDP.
// Runs a single read loop and spawns a goroutine for each packet.
func (t *UDPTransport) Serve(handler TransportHandler) error {
	for {
		// Get buffer from pool
		bufPtr := udpBufferPool.Get().(*[]byte)
		buffer := *bufPtr

		n, addr, err := t.conn.ReadFrom(buffer)
		if err != nil {
			udpBufferPool.Put(bufPtr)

			t.mu.RLock()
			closed := t.closed
			t.mu.RUnlock()

			if closed {
				return nil
			}

			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			return err
		}

		// Copy data to new slice before passing to goroutine
		data := make([]byte, n)
		copy(data, buffer[:n])
		udpBufferPool.Put(bufPtr)

		// Create responder for this address
		respond := func(respData []byte) error {
			_, err := t.conn.WriteTo(respData, addr)
			return err
		}

		t.wg.Add(1)
		go func() {
			defer t.wg.Done()
			handler(data, addr, respond)
		}()
	}
}

// LocalAddr implements Transport.LocalAddr.
func (t *UDPTransport) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// Close implements Transport.Close.
// Closes the connection and waits for all in-flight handlers to complete.
func (t *UDPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	err := t.conn.Close()
	t.wg.Wait()
	return err
}
