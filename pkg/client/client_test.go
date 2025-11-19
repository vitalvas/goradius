package client

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestNew(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	client, err := New(Config{
		Addr:       "127.0.0.1:3799",
		Secret:     []byte("testing123"),
		Dictionary: dict,
	})
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "127.0.0.1:3799", client.addr)
	assert.Equal(t, []byte("testing123"), client.secret)
	assert.Equal(t, dict, client.dict)
	assert.Equal(t, 3*time.Second, client.timeout)
}

func TestNewWithCustomTimeout(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	client, err := New(Config{
		Addr:       "127.0.0.1:3799",
		Secret:     []byte("testing123"),
		Dictionary: dict,
		Timeout:    5 * time.Second,
	})
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, 5*time.Second, client.timeout)
}

func TestCoA(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := packet.Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, packet.CodeCoARequest, reqPkt.Code)

		respPkt := packet.New(packet.CodeCoAACK, reqPkt.Identifier)
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := New(Config{
		Addr:       serverAddr.String(),
		Secret:     []byte("testing123"),
		Dictionary: dict,
		Timeout:    2 * time.Second,
	})
	require.NoError(t, err)

	resp, err := client.CoA(map[string]interface{}{
		"User-Name":       "testuser",
		"Session-Timeout": uint32(3600),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, packet.CodeCoAACK, resp.Code)
}

func TestDisconnect(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := packet.Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, packet.CodeDisconnectRequest, reqPkt.Code)

		respPkt := packet.New(packet.CodeDisconnectACK, reqPkt.Identifier)
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := New(Config{
		Addr:       serverAddr.String(),
		Secret:     []byte("testing123"),
		Dictionary: dict,
		Timeout:    2 * time.Second,
	})
	require.NoError(t, err)

	resp, err := client.Disconnect(map[string]interface{}{
		"User-Name": "testuser",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, packet.CodeDisconnectACK, resp.Code)
}

func TestCoAWithInvalidAttribute(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	client, err := New(Config{
		Addr:       "127.0.0.1:3799",
		Secret:     []byte("testing123"),
		Dictionary: dict,
	})
	require.NoError(t, err)

	_, err = client.CoA(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestDisconnectWithInvalidAttribute(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	client, err := New(Config{
		Addr:       "127.0.0.1:3799",
		Secret:     []byte("testing123"),
		Dictionary: dict,
	})
	require.NoError(t, err)

	_, err = client.Disconnect(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestTimeout(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	client, err := New(Config{
		Addr:       serverAddr.String(),
		Secret:     []byte("testing123"),
		Dictionary: dict,
		Timeout:    100 * time.Millisecond,
	})
	require.NoError(t, err)

	_, err = client.CoA(map[string]interface{}{
		"User-Name": "testuser",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestAccessRequest(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := packet.Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, packet.CodeAccessRequest, reqPkt.Code)

		respPkt := packet.New(packet.CodeAccessAccept, reqPkt.Identifier)
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := New(Config{
		Addr:       serverAddr.String(),
		Secret:     []byte("testing123"),
		Dictionary: dict,
		Timeout:    2 * time.Second,
	})
	require.NoError(t, err)

	resp, err := client.AccessRequest(map[string]interface{}{
		"User-Name":     "testuser",
		"User-Password": "testpass",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, packet.CodeAccessAccept, resp.Code)
}

func TestAccountingRequest(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := packet.Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, packet.CodeAccountingRequest, reqPkt.Code)

		respPkt := packet.New(packet.CodeAccountingResponse, reqPkt.Identifier)
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := New(Config{
		Addr:       serverAddr.String(),
		Secret:     []byte("testing123"),
		Dictionary: dict,
		Timeout:    2 * time.Second,
	})
	require.NoError(t, err)

	resp, err := client.AccountingRequest(map[string]interface{}{
		"User-Name":         "testuser",
		"Acct-Status-Type":  uint32(1), // Start
		"Acct-Session-Id":   "session123",
		"NAS-IP-Address":    "192.0.2.1",
		"Acct-Session-Time": uint32(100),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, packet.CodeAccountingResponse, resp.Code)
}

func TestAccessRequestWithInvalidAttribute(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	client, err := New(Config{
		Addr:       "127.0.0.1:1812",
		Secret:     []byte("testing123"),
		Dictionary: dict,
	})
	require.NoError(t, err)

	_, err = client.AccessRequest(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestAccountingRequestWithInvalidAttribute(t *testing.T) {
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	client, err := New(Config{
		Addr:       "127.0.0.1:1813",
		Secret:     []byte("testing123"),
		Dictionary: dict,
	})
	require.NoError(t, err)

	_, err = client.AccountingRequest(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}
