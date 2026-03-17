package goradius

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewUDPTransport(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer conn.Close()

	transport := NewUDPTransport(conn)
	assert.NotNil(t, transport)
	assert.Equal(t, conn.LocalAddr(), transport.LocalAddr())
}

func TestUDPTransportServeAndClose(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	transport := NewUDPTransport(conn)

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

	// Send a packet
	clientConn, err := net.DialUDP("udp", nil, conn.LocalAddr().(*net.UDPAddr))
	require.NoError(t, err)
	defer clientConn.Close()

	reqPkt := NewPacket(CodeAccessRequest, 1)
	data, _ := reqPkt.Encode()
	_, err = clientConn.Write(data)
	require.NoError(t, err)

	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, int32(1), called.Load())

	require.NoError(t, transport.Close())
	err = <-errCh
	assert.NoError(t, err)
}

func TestUDPTransportDoubleClose(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)

	transport := NewUDPTransport(conn)

	go transport.Serve(func([]byte, net.Addr, ResponderFunc) {})
	time.Sleep(50 * time.Millisecond)

	require.NoError(t, transport.Close())
	assert.NoError(t, transport.Close())
}

func TestUDPTransportLocalAddr(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer conn.Close()

	transport := NewUDPTransport(conn)
	addr := transport.LocalAddr()
	assert.NotNil(t, addr)
	assert.Equal(t, "udp", addr.Network())
}
