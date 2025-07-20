package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestNewDefaultHandler(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		logger := log.NewDefaultLogger()
		handler := NewDefaultHandler(logger)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.clients)
		assert.Equal(t, logger, handler.logger)
		assert.Nil(t, handler.AuthCallback)
		assert.Nil(t, handler.AccountingCallback)
	})

	t.Run("with nil logger", func(t *testing.T) {
		handler := NewDefaultHandler(nil)

		assert.NotNil(t, handler)
		assert.NotNil(t, handler.logger) // Should create default logger
	})
}

func TestDefaultHandler_AddClient(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	client := &ClientConfig{
		Networks: []string{"192.168.1.0/24", "10.0.0.1"},
		Secret:   "test-secret",
		Name:     "test-client",
	}

	handler.AddClient(client)

	// Verify client was added for all networks
	assert.Len(t, handler.clients, 2)
	assert.Equal(t, client, handler.clients["192.168.1.0/24"])
	assert.Equal(t, client, handler.clients["10.0.0.1"])
}

func TestDefaultHandler_GetSharedSecret(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	client := &ClientConfig{
		Networks: []string{"192.168.1.0/24", "127.0.0.1"},
		Secret:   "test-secret-123",
		Name:     "test-client",
	}
	handler.AddClient(client)

	t.Run("valid client in CIDR range", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}
		secret, err := handler.GetSharedSecret(clientAddr)

		require.NoError(t, err)
		assert.Equal(t, []byte("test-secret-123"), secret)
	})

	t.Run("valid client exact IP", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		secret, err := handler.GetSharedSecret(clientAddr)

		require.NoError(t, err)
		assert.Equal(t, []byte("test-secret-123"), secret)
	})

	t.Run("invalid client", func(t *testing.T) {
		clientAddr := &net.UDPAddr{IP: net.ParseIP("172.16.1.1"), Port: 12345}
		secret, err := handler.GetSharedSecret(clientAddr)

		assert.Error(t, err)
		assert.Nil(t, secret)
		assert.Contains(t, err.Error(), "no shared secret found")
	})

	t.Run("unsupported address type", func(t *testing.T) {
		clientAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
		secret, err := handler.GetSharedSecret(clientAddr)

		assert.Error(t, err)
		assert.Nil(t, secret)
		assert.Contains(t, err.Error(), "unsupported address type")
	})
}

func TestDefaultHandler_HandleAuthRequest(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	t.Run("Access-Request without username", func(t *testing.T) {
		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeAccessRequest,
				Identifier: 1,
				Length:     packet.PacketHeaderLength,
				Attributes: []packet.Attribute{},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccessReject, response.Packet.Code)
		assert.Equal(t, req.Packet.Identifier, response.Packet.Identifier)
	})

	t.Run("Access-Request with username", func(t *testing.T) {
		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeAccessRequest,
				Identifier: 1,
				Length:     packet.PacketHeaderLength,
				Attributes: []packet.Attribute{
					packet.NewStringAttribute(packet.AttrUserName, "test"),
				},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccessAccept, response.Packet.Code)
		assert.Equal(t, req.Packet.Identifier, response.Packet.Identifier)
	})

	t.Run("Access-Request with auth callback success", func(t *testing.T) {
		handler.SetAuthCallback(func(username, password string) bool {
			return username == "testuser" && password == "testpass"
		})

		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeAccessRequest,
				Identifier: 1,
				Length:     packet.PacketHeaderLength,
				Attributes: []packet.Attribute{
					packet.NewStringAttribute(packet.AttrUserName, "testuser"),
					packet.NewStringAttribute(packet.AttrUserPassword, "testpass"),
				},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccessAccept, response.Packet.Code)
	})

	t.Run("Access-Request with auth callback failure", func(t *testing.T) {
		handler.SetAuthCallback(func(_, _ string) bool {
			return false // Always fail
		})

		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeAccessRequest,
				Identifier: 1,
				Attributes: []packet.Attribute{
					{
						Type:   packet.AttrUserName,
						Length: 10,
						Value:  []byte("testuser"),
					},
				},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccessReject, response.Packet.Code)
	})

	t.Run("accounting request handled correctly", func(t *testing.T) {
		req := &Request{
			Packet: &packet.Packet{
				Code:       packet.CodeAccountingRequest,
				Identifier: 1,
			},
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, packet.CodeAccountingResponse, response.Packet.Code)
	})
}

func TestDefaultHandler_HandleAccountingRequest(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	t.Run("Accounting-Request without callback", func(t *testing.T) {
		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeAccountingRequest,
				Identifier: 2,
				Attributes: []packet.Attribute{},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccountingResponse, response.Packet.Code)
		assert.Equal(t, req.Packet.Identifier, response.Packet.Identifier)
	})

	t.Run("Accounting-Request with callback", func(t *testing.T) {
		callbackCalled := false
		handler.SetAccountingCallback(func(_ *Request) error {
			callbackCalled = true
			return nil
		})

		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeAccountingRequest,
				Identifier: 2,
				Attributes: []packet.Attribute{},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, callbackCalled)
		assert.Equal(t, packet.CodeAccountingResponse, response.Packet.Code)
	})

	t.Run("access request handled correctly", func(t *testing.T) {
		req := &Request{
			Packet: &packet.Packet{
				Code:       packet.CodeAccessRequest,
				Identifier: 1,
			},
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, packet.CodeAccessReject, response.Packet.Code)
	})
}

func TestDefaultHandler_HandleCoARequest(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	t.Run("CoA-Request", func(t *testing.T) {
		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeCoARequest,
				Identifier: 3,
				Attributes: []packet.Attribute{},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeCoAAck, response.Packet.Code)
		assert.Equal(t, req.Packet.Identifier, response.Packet.Identifier)
	})

	t.Run("Disconnect-Request", func(t *testing.T) {
		req := &Request{
			ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
			Packet: &packet.Packet{
				Code:       packet.CodeDisconnectRequest,
				Identifier: 4,
				Attributes: []packet.Attribute{},
			},
			ReceivedAt: time.Now(),
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeDisconnectACK, response.Packet.Code)
		assert.Equal(t, req.Packet.Identifier, response.Packet.Identifier)
	})

	t.Run("access request handled correctly", func(t *testing.T) {
		req := &Request{
			Packet: &packet.Packet{
				Code:       packet.CodeAccessRequest,
				Identifier: 1,
			},
		}

		ctx := context.Background()
		response, err := handler.HandleRequest(ctx, req)

		require.NoError(t, err)
		require.NotNil(t, response)
		assert.Equal(t, packet.CodeAccessReject, response.Packet.Code)
	})
}

func TestDefaultHandler_UnsupportedPacketCode(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	req := &Request{
		Packet: &packet.Packet{
			Code:       255, // Invalid packet code
			Identifier: 1,
		},
	}

	ctx := context.Background()
	response, err := handler.HandleRequest(ctx, req)

	assert.Error(t, err)
	assert.Nil(t, response)
	assert.Contains(t, err.Error(), "unsupported packet code")
}

func TestDefaultHandler_ResponseCreation(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	req := &Request{
		Packet: &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 42,
		},
	}

	t.Run("Access-Accept", func(t *testing.T) {
		response := handler.createAccessAccept(req)

		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccessAccept, response.Packet.Code)
		assert.Equal(t, uint8(42), response.Packet.Identifier)
		assert.NotNil(t, response.Packet.Attributes)
	})

	t.Run("Access-Reject with message", func(t *testing.T) {
		message := "Authentication failed"
		response := handler.createAccessReject(req, message)

		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccessReject, response.Packet.Code)
		assert.Equal(t, uint8(42), response.Packet.Identifier)

		// Check for Reply-Message attribute
		require.Len(t, response.Packet.Attributes, 1)
		attr := response.Packet.Attributes[0]
		assert.Equal(t, packet.AttrReplyMessage, attr.Type)
		assert.Equal(t, message, string(attr.Value))
	})

	t.Run("Access-Reject without message", func(t *testing.T) {
		response := handler.createAccessReject(req, "")

		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccessReject, response.Packet.Code)
		assert.Empty(t, response.Packet.Attributes)
	})

	t.Run("Accounting-Response", func(t *testing.T) {
		response := handler.createAccountingResponse(req)

		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeAccountingResponse, response.Packet.Code)
		assert.Equal(t, uint8(42), response.Packet.Identifier)
	})

	t.Run("CoA-ACK", func(t *testing.T) {
		response := handler.createCoAAck(req)

		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeCoAAck, response.Packet.Code)
		assert.Equal(t, uint8(42), response.Packet.Identifier)
	})

	t.Run("Disconnect-ACK", func(t *testing.T) {
		response := handler.createDisconnectAck(req)

		require.NotNil(t, response)
		assert.True(t, response.Send)
		assert.Equal(t, packet.CodeDisconnectACK, response.Packet.Code)
		assert.Equal(t, uint8(42), response.Packet.Identifier)
	})
}

func TestDefaultHandler_isIPInNetwork(t *testing.T) {

	testCases := []struct {
		name     string
		ip       string
		network  string
		expected bool
	}{
		{"IPv4 in CIDR", "192.168.1.100", "192.168.1.0/24", true},
		{"IPv4 not in CIDR", "192.168.2.100", "192.168.1.0/24", false},
		{"IPv4 exact match", "10.0.0.1", "10.0.0.1", true},
		{"IPv4 no match", "10.0.0.2", "10.0.0.1", false},
		{"Invalid network", "192.168.1.1", "invalid", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ip := net.ParseIP(tc.ip)
			require.NotNil(t, ip)

			result := isIPInNetwork(ip, tc.network)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestDefaultHandler_Concurrency(t *testing.T) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	// Add multiple clients concurrently
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func(id int) {
			client := &ClientConfig{
				Networks: []string{net.IPv4(192, 168, byte(id), 0).String() + "/24"},
				Secret:   "secret",
				Name:     "client",
			}
			handler.AddClient(client)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all clients were added
	assert.Len(t, handler.clients, 10)
}

// Benchmark handler request processing
func BenchmarkHandleRequest(b *testing.B) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	req := &Request{
		ClientAddr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345},
		Packet: &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Attributes: []packet.Attribute{
				{
					Type:   packet.AttrUserName,
					Length: 6,
					Value:  []byte("test"),
				},
			},
		},
		ReceivedAt: time.Now(),
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := handler.HandleRequest(ctx, req)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// Benchmark shared secret lookup
func BenchmarkGetSharedSecret(b *testing.B) {
	handler := NewDefaultHandler(log.NewDefaultLogger())

	client := &ClientConfig{
		Networks: []string{"192.168.1.0/24"},
		Secret:   "test-secret",
	}
	handler.AddClient(client)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := handler.GetSharedSecret(clientAddr)
		if err != nil {
			b.Fatal(err)
		}
	}
}
