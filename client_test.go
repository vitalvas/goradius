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
		"user-name":       "testuser",
		"session-timeout": uint32(3600),
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
		"user-name": "testuser",
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
		"invalid-attribute": "value",
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
		"invalid-attribute": "value",
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
		"user-name": "testuser",
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
		"user-name":     "testuser",
		"user-password": "testpass",
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
		"user-name":         "testuser",
		"acct-status-type":  uint32(1), // Start
		"acct-session-id":   "session123",
		"nas-ip-address":    "192.0.2.1",
		"acct-session-time": uint32(100),
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
		"invalid-attribute": "value",
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
		"invalid-attribute": "value",
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
		"user-name":     "testuser",
		"user-password": "testpass",
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
		"user-name":     "testuser",
		"user-password": "testpass",
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
		"user-name":         "testuser",
		"acct-status-type":  uint32(1),
		"acct-session-id":   "session123",
		"nas-ip-address":    "192.0.2.1",
		"acct-session-time": uint32(100),
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
		"user-name":       "testuser",
		"session-timeout": uint32(3600),
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
		"user-name": "testuser",
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, _ = client.Disconnect(attrs)
	}
}

func TestClientAcceptsAccountingResponseWithoutMessageAuthenticator(t *testing.T) {
	// RFC 2866 servers legitimately omit Message-Authenticator from
	// Accounting-Response; the default client must interoperate with them.
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

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

		respPkt := NewPacket(CodeAccountingResponse, reqPkt.Identifier)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverConn.LocalAddr().String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)
	require.NoError(t, err)

	resp, err := client.AccountingRequest(map[string]interface{}{"user-name": "testuser"})
	require.NoError(t, err)
	assert.Equal(t, CodeAccountingResponse, resp.Code)
}

func TestClientDiscardsForgedMessageAuthenticatorWhenVerificationDisabled(t *testing.T) {
	// RFC 3579 Section 3.2: a present Message-Authenticator must verify even
	// when the client is configured not to require one. RFC 2865 Section 4.2:
	// the invalid datagram is silently discarded, so with no genuine response
	// following it the request times out instead of accepting the forgery.
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

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

		respPkt := NewPacket(CodeAccessAccept, reqPkt.Identifier)
		respPkt.AddMessageAuthenticator([]byte("wrong-secret"), reqPkt.Authenticator)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverConn.LocalAddr().String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(300*time.Millisecond),
		WithVerifyMessageAuthenticator(false),
	)
	require.NoError(t, err)

	_, err = client.AccessRequest(map[string]interface{}{"user-name": "testuser"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read response")
}

func TestClientTransparentResponseDecryption(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	secret := []byte("testing123")
	mppeKey := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04}

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

		// Build the reply through the dictionary API only: the MPPE key is
		// salt-encrypted transparently with the request authenticator.
		respPkt := NewPacketWithDictionary(CodeAccessAccept, reqPkt.Identifier, dict)
		respPkt.Secret = secret
		respPkt.bindRequestAuthenticator(reqPkt.Authenticator)
		if err := respPkt.AddAttributeByName("ms-mppe-send-key", mppeKey); err != nil {
			return
		}
		respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, err := respPkt.Encode()
		if err != nil {
			return
		}
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverConn.LocalAddr().String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)
	require.NoError(t, err)

	resp, err := client.AccessRequest(map[string]interface{}{
		"user-name":     "testuser",
		"user-password": "testpass",
	})
	require.NoError(t, err)
	require.Equal(t, CodeAccessAccept, resp.Code)

	// The client reads the plaintext key with no manual decryption.
	values := resp.GetAttribute("ms-mppe-send-key")
	require.Len(t, values, 1)
	assert.Equal(t, mppeKey, values[0].Value)
}

func TestClientIgnoresStrayDatagrams(t *testing.T) {
	// RFC 2865 Section 4.2: invalid packets are silently discarded, so
	// stray or spoofed datagrams must not abort the exchange while the
	// genuine response is still on its way.
	dict, err := NewDefault()
	require.NoError(t, err)

	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

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

		// Garbage that does not decode.
		serverConn.WriteToUDP([]byte{0x01, 0x02, 0x03}, clientAddr)

		// A well-formed packet with the wrong identifier.
		stray := NewPacket(CodeAccessAccept, reqPkt.Identifier+1)
		stray.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		stray.SetAuthenticator(stray.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		strayData, _ := stray.Encode()
		serverConn.WriteToUDP(strayData, clientAddr)

		// The genuine response.
		respPkt := NewPacket(CodeAccessAccept, reqPkt.Identifier)
		respPkt.AddMessageAuthenticator(secret, reqPkt.Authenticator)
		respPkt.SetAuthenticator(respPkt.CalculateResponseAuthenticator(secret, reqPkt.Authenticator))
		respData, _ := respPkt.Encode()
		serverConn.WriteToUDP(respData, clientAddr)
	}()

	client, err := NewClient(
		WithAddr(serverConn.LocalAddr().String()),
		WithSecret(secret),
		WithClientDictionary(dict),
		WithTimeout(2*time.Second),
	)
	require.NoError(t, err)

	resp, err := client.AccessRequest(map[string]interface{}{"user-name": "testuser"})
	require.NoError(t, err)
	assert.Equal(t, CodeAccessAccept, resp.Code)
}

func TestClientCloseUnblocksInflightRequest(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	// A server that never replies: the request blocks until deadline or Close.
	serverConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	defer serverConn.Close()

	client, err := NewClient(
		WithAddr(serverConn.LocalAddr().String()),
		WithSecret([]byte("testing123")),
		WithClientDictionary(dict),
		WithTimeout(3*time.Second),
	)
	require.NoError(t, err)

	errCh := make(chan error, 1)
	go func() {
		_, err := client.AccessRequest(map[string]interface{}{"user-name": "testuser"})
		errCh <- err
	}()

	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	require.NoError(t, client.Close())

	select {
	case err := <-errCh:
		require.ErrorIs(t, err, ErrClientClosed)
		assert.Less(t, time.Since(start), time.Second, "Close must unblock the in-flight request promptly")
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight request was not unblocked by Close")
	}
}
