package goradius

import (
	"bytes"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTCPTransport(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	transport := NewTCPTransport(listener)
	assert.NotNil(t, transport)
	assert.Equal(t, listener.Addr(), transport.LocalAddr())
}

func TestTCPTransportServeAndClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	var called atomic.Int32
	handler := func(data []byte, _ net.Addr, respond ResponderFunc) {
		called.Add(1)
		respond(data)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- transport.Serve(handler)
	}()

	time.Sleep(50 * time.Millisecond)

	// Connect and send a packet
	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	reqPkt := NewPacket(CodeAccessRequest, 1)
	data, _ := reqPkt.Encode()
	_, err = conn.Write(data)
	require.NoError(t, err)

	// Read response
	conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)

	conn.Close()
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), called.Load())

	require.NoError(t, transport.Close())
	err = <-errCh
	assert.NoError(t, err)
}

func TestTCPTransportDoubleClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	transport := NewTCPTransport(listener)

	go transport.Serve(func([]byte, net.Addr, ResponderFunc) {})
	time.Sleep(50 * time.Millisecond)

	require.NoError(t, transport.Close())
	assert.NoError(t, transport.Close())
}

func TestTCPTransportLocalAddr(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	transport := NewTCPTransport(listener)
	addr := transport.LocalAddr()
	assert.NotNil(t, addr)
	assert.Equal(t, "tcp", addr.Network())
}

func TestReadRADIUSPacket(t *testing.T) {
	t.Run("valid packet", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		data, _ := pkt.Encode()

		result, err := readRADIUSPacket(bytes.NewReader(data))
		require.NoError(t, err)
		assert.Equal(t, data, result)
	})

	t.Run("header only packet", func(t *testing.T) {
		// Minimal valid RADIUS packet (20 bytes header, no attributes)
		pkt := NewPacket(CodeAccessRequest, 1)
		data, _ := pkt.Encode()

		result, err := readRADIUSPacket(bytes.NewReader(data))
		require.NoError(t, err)
		assert.Len(t, result, int(PacketHeaderLength))
	})

	t.Run("truncated header", func(t *testing.T) {
		data := []byte{0x01, 0x01} // Only 2 bytes
		_, err := readRADIUSPacket(bytes.NewReader(data))
		assert.Error(t, err)
	})

	t.Run("empty reader", func(t *testing.T) {
		_, err := readRADIUSPacket(bytes.NewReader(nil))
		assert.ErrorIs(t, err, io.EOF)
	})

	t.Run("too short length field", func(t *testing.T) {
		header := make([]byte, PacketHeaderLength)
		header[0] = byte(CodeAccessRequest)
		header[1] = 1
		header[2] = 0
		header[3] = 10 // Length < MinPacketLength
		_, err := readRADIUSPacket(bytes.NewReader(header))
		assert.Error(t, err)
	})

	t.Run("too long length field", func(t *testing.T) {
		header := make([]byte, PacketHeaderLength)
		header[0] = byte(CodeAccessRequest)
		header[1] = 1
		header[2] = 0xFF // Length > MaxPacketLength
		header[3] = 0xFF
		_, err := readRADIUSPacket(bytes.NewReader(header))
		assert.Error(t, err)
	})
}
