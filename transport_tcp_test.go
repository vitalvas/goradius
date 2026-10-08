package goradius

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"syscall"
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

func TestIsTemporaryAcceptError(t *testing.T) {
	temporary := []error{
		&net.OpError{Op: "accept", Err: &os.SyscallError{Syscall: "accept", Err: syscall.EMFILE}},
		&net.OpError{Op: "accept", Err: &os.SyscallError{Syscall: "accept", Err: syscall.ENFILE}},
		&net.OpError{Op: "accept", Err: &os.SyscallError{Syscall: "accept", Err: syscall.ECONNABORTED}},
	}
	for _, err := range temporary {
		assert.True(t, isTemporaryAcceptError(err), "%v should be temporary", err)
	}

	assert.False(t, isTemporaryAcceptError(errors.New("boom")))
	assert.False(t, isTemporaryAcceptError(net.ErrClosed))
}

// TestTCPTransportCloseAcceptRace exercises the shutdown path with
// connections arriving concurrently with Close; run with -race it verifies
// the accept/close interleaving cannot Add to the WaitGroup after Wait or
// leak an untracked connection.
func TestTCPTransportCloseAcceptRace(t *testing.T) {
	for range 20 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)

		transport := NewTCPTransport(listener)
		served := make(chan error, 1)
		go func() {
			served <- transport.Serve(func([]byte, net.Addr, ResponderFunc) {})
		}()

		addr := listener.Addr().String()
		go func() {
			if conn, err := net.Dial("tcp", addr); err == nil {
				conn.Close()
			}
		}()

		require.NoError(t, transport.Close())
		assert.NoError(t, <-served)
	}
}
