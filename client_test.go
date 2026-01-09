package goradius

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	client, err := NewClient(
		WithAddr("127.0.0.1:3799"),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
	)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, "127.0.0.1:3799", client.addr)
	assert.Equal(t, []byte("testing123"), client.secret)
	assert.Equal(t, dict, client.dict)
	assert.Equal(t, 3*time.Second, client.timeout)
}

func TestNewWithCustomTimeout(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	client, err := NewClient(
		WithAddr("127.0.0.1:3799"),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
		WithTimeout(5*time.Second),
	)
	require.NoError(t, err)
	assert.NotNil(t, client)
	assert.Equal(t, 5*time.Second, client.timeout)
}

func TestCoA(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	secret := []byte("testing123")
	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, CodeCoARequest, reqPkt.Code)

		respPkt := NewPacket(CodeCoAACK, reqPkt.Identifier)
		respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)
	require.NoError(t, err)

	resp, err := client.CoA(map[string]interface{}{
		"User-Name":       "testuser",
		"Session-Timeout": uint32(3600),
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, CodeCoAACK, resp.Code)
}

func TestDisconnect(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	secret := []byte("testing123")
	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, CodeDisconnectRequest, reqPkt.Code)

		respPkt := NewPacket(CodeDisconnectACK, reqPkt.Identifier)
		respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)
	require.NoError(t, err)

	resp, err := client.Disconnect(map[string]interface{}{
		"User-Name": "testuser",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, CodeDisconnectACK, resp.Code)
}

func TestCoAWithInvalidAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	client, err := NewClient(
		WithAddr("127.0.0.1:3799"),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
	)
	require.NoError(t, err)

	_, err = client.CoA(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestDisconnectWithInvalidAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	client, err := NewClient(
		WithAddr("127.0.0.1:3799"),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
	)
	require.NoError(t, err)

	_, err = client.Disconnect(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestTimeout(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	client, err := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
		WithTimeout(100*time.Millisecond),
	)
	require.NoError(t, err)

	_, err = client.CoA(map[string]interface{}{
		"User-Name": "testuser",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timeout")
}

func TestAccessRequest(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	secret := []byte("testing123")
	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, CodeAccessRequest, reqPkt.Code)

		respPkt := NewPacket(CodeAccessAccept, reqPkt.Identifier)
		respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)
	require.NoError(t, err)

	resp, err := client.AccessRequest(map[string]interface{}{
		"User-Name":     "testuser",
		"User-Password": "testpass",
	})
	require.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, CodeAccessAccept, resp.Code)
}

func TestAccountingRequest(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	secret := []byte("testing123")
	go func() {
		buffer := make([]byte, 4096)
		n, clientAddr, err := serverConn.ReadFromUDP(buffer)
		if err != nil {
			return
		}

		reqPkt, err := Decode(buffer[:n])
		if err != nil {
			return
		}

		assert.Equal(t, CodeAccountingRequest, reqPkt.Code)

		respPkt := NewPacket(CodeAccountingResponse, reqPkt.Identifier)
		respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)
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
	assert.Equal(t, CodeAccountingResponse, resp.Code)
}

func TestAccessRequestWithInvalidAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	client, err := NewClient(
		WithAddr("127.0.0.1:1812"),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
	)
	require.NoError(t, err)

	_, err = client.AccessRequest(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

func TestAccountingRequestWithInvalidAttribute(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	client, err := NewClient(
		WithAddr("127.0.0.1:1813"),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
	)
	require.NoError(t, err)

	_, err = client.AccountingRequest(map[string]interface{}{
		"Invalid-Attribute": "value",
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found in dictionary")
}

// Benchmarks

func BenchmarkClientNew(b *testing.B) {
	dict, _ := NewDefault()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = NewClient(
			WithAddr("127.0.0.1:1812"),
			WithSecret([]byte("testing123")),
			WithClientDictionary(dict),
		)
	}
}

func BenchmarkClientAccessRequest(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	// Mock server
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		for {
			n, clientAddr, err := serverConn.ReadFromUDP(buffer)
			if err != nil {
				return
			}

			reqPkt, err := Decode(buffer[:n])
			if err != nil {
				continue
			}

			respPkt := NewPacket(CodeAccessAccept, reqPkt.Identifier)
			respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
			respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
			respData, _ := respPkt.Encode()
			serverConn.WriteToUDP(respData, clientAddr)
		}
	}()

	client, _ := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)

	attrs := map[string]interface{}{
		"User-Name":     "testuser",
		"User-Password": "testpass",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.AccessRequest(attrs)
	}
}

func BenchmarkClientAccessRequestParallel(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	// Mock server
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		for {
			n, clientAddr, err := serverConn.ReadFromUDP(buffer)
			if err != nil {
				return
			}

			reqPkt, err := Decode(buffer[:n])
			if err != nil {
				continue
			}

			respPkt := NewPacket(CodeAccessAccept, reqPkt.Identifier)
			respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
			respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
			respData, _ := respPkt.Encode()
			serverConn.WriteToUDP(respData, clientAddr)
		}
	}()

	client, _ := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)

	attrs := map[string]interface{}{
		"User-Name":     "testuser",
		"User-Password": "testpass",
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = client.AccessRequest(attrs)
		}
	})
}

func BenchmarkClientAccountingRequest(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	// Mock server
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		for {
			n, clientAddr, err := serverConn.ReadFromUDP(buffer)
			if err != nil {
				return
			}

			reqPkt, err := Decode(buffer[:n])
			if err != nil {
				continue
			}

			respPkt := NewPacket(CodeAccountingResponse, reqPkt.Identifier)
			respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
			respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
			respData, _ := respPkt.Encode()
			serverConn.WriteToUDP(respData, clientAddr)
		}
	}()

	client, _ := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)

	attrs := map[string]interface{}{
		"User-Name":         "testuser",
		"Acct-Status-Type":  uint32(1),
		"Acct-Session-Id":   "session123",
		"NAS-IP-Address":    "192.0.2.1",
		"Acct-Session-Time": uint32(100),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.AccountingRequest(attrs)
	}
}

func BenchmarkClientCoA(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	// Mock server
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		for {
			n, clientAddr, err := serverConn.ReadFromUDP(buffer)
			if err != nil {
				return
			}

			reqPkt, err := Decode(buffer[:n])
			if err != nil {
				continue
			}

			respPkt := NewPacket(CodeCoAACK, reqPkt.Identifier)
			respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
			respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
			respData, _ := respPkt.Encode()
			serverConn.WriteToUDP(respData, clientAddr)
		}
	}()

	client, _ := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)

	attrs := map[string]interface{}{
		"User-Name":       "testuser",
		"Session-Timeout": uint32(3600),
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.CoA(attrs)
	}
}

func BenchmarkClientDisconnect(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	// Mock server
	serverConn, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	defer serverConn.Close()

	serverAddr := serverConn.LocalAddr().(*net.UDPAddr)

	go func() {
		buffer := make([]byte, 4096)
		for {
			n, clientAddr, err := serverConn.ReadFromUDP(buffer)
			if err != nil {
				return
			}

			reqPkt, err := Decode(buffer[:n])
			if err != nil {
				continue
			}

			respPkt := NewPacket(CodeDisconnectACK, reqPkt.Identifier)
			respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
			respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
			respData, _ := respPkt.Encode()
			serverConn.WriteToUDP(respData, clientAddr)
		}
	}()

	client, _ := NewClient(
		WithAddr(serverAddr.String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)

	attrs := map[string]interface{}{
		"User-Name": "testuser",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.Disconnect(attrs)
	}
}
