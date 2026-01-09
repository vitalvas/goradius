package goradius

import (
	"encoding/binary"
	"io"
	"net"
	"sync"

)

// TCPTransport implements Transport for TCP/TLS connections.
// Supports RADIUS over TCP (RFC 6613) with multiple packets per connection.
type TCPTransport struct {
	listener net.Listener
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	mu       sync.RWMutex
	closed   bool
}

// NewTCPTransport creates a TCP transport from an existing Listener.
// Works with both net.Listener (TCP) and tls.Listener (TLS).
func NewTCPTransport(listener net.Listener) *TCPTransport {
	return &TCPTransport{
		listener: listener,
		conns:    make(map[net.Conn]struct{}),
	}
}

// Serve implements Transport.Serve for TCP.
// Runs an accept loop and spawns a goroutine for each connection.
func (t *TCPTransport) Serve(handler TransportHandler) error {
	for {
		conn, err := t.listener.Accept()
		if err != nil {
			t.mu.RLock()
			closed := t.closed
			t.mu.RUnlock()

			if closed {
				return nil
			}

			return err
		}

		t.trackConn(conn, true)
		t.wg.Add(1)
		go t.handleConnection(conn, handler)
	}
}

// trackConn adds or removes a connection from tracking.
func (t *TCPTransport) trackConn(conn net.Conn, add bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if add {
		t.conns[conn] = struct{}{}
	} else {
		delete(t.conns, conn)
	}
}

// handleConnection reads RADIUS packets from a single TCP connection.
func (t *TCPTransport) handleConnection(conn net.Conn, handler TransportHandler) {
	defer t.wg.Done()
	defer t.trackConn(conn, false)
	defer conn.Close()

	remoteAddr := conn.RemoteAddr()

	for {
		data, err := readRADIUSPacket(conn)
		if err != nil {
			return // Connection closed or error
		}

		// Create responder that writes to this connection
		respond := func(respData []byte) error {
			_, err := conn.Write(respData)
			return err
		}

		t.wg.Add(1)
		go func(pktData []byte) {
			defer t.wg.Done()
			handler(pktData, remoteAddr, respond)
		}(data)
	}
}

// readRADIUSPacket reads a single framed RADIUS packet from a TCP stream.
// Uses the Length field in bytes 2-3 for packet boundary detection.
func readRADIUSPacket(r io.Reader) ([]byte, error) {
	// Read header first (20 bytes minimum)
	header := make([]byte, PacketHeaderLength)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}

	// Extract length from bytes 2-3 (big-endian)
	length := binary.BigEndian.Uint16(header[2:4])

	// Validate length
	if length < MinPacketLength {
		return nil, io.ErrUnexpectedEOF
	}
	if length > MaxPacketLength {
		return nil, io.ErrUnexpectedEOF
	}

	// If packet is just header (no attributes), return it
	if length == PacketHeaderLength {
		return header, nil
	}

	// Read remaining bytes (attributes)
	data := make([]byte, length)
	copy(data, header)
	if _, err := io.ReadFull(r, data[PacketHeaderLength:]); err != nil {
		return nil, err
	}

	return data, nil
}

// LocalAddr implements Transport.LocalAddr.
func (t *TCPTransport) LocalAddr() net.Addr {
	return t.listener.Addr()
}

// Close implements Transport.Close.
// Closes the listener and all active connections, then waits for handlers to complete.
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true

	// Close listener first
	err := t.listener.Close()

	// Close all active connections
	for conn := range t.conns {
		conn.Close()
	}
	t.mu.Unlock()

	// Wait for all handlers to complete
	t.wg.Wait()
	return err
}
