package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/crypto"
	"github.com/vitalvas/goradius/pkg/log"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestLoggingMiddleware(t *testing.T) {
	logger := log.NewDefaultLogger()
	middleware := LoggingMiddleware(logger)

	clientCtx := &ClientContext{
		RequestID: 123,
		Addr:      &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
	}

	req := &packet.Packet{
		Code:       packet.CodeAccessRequest,
		Identifier: 1,
	}

	t.Run("successful request", func(t *testing.T) {
		nextCalled := false
		next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			nextCalled = true
			return &HandlerResult{
				Response: &packet.Packet{Code: packet.CodeAccessAccept},
				Send:     true,
			}, nil
		}

		result, err := middleware(context.Background(), clientCtx, req, next)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, nextCalled)
		assert.Equal(t, packet.CodeAccessAccept, result.Response.Code)
	})

	t.Run("failed request", func(t *testing.T) {
		nextCalled := false
		next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			nextCalled = true
			return nil, assert.AnError
		}

		result, err := middleware(context.Background(), clientCtx, req, next)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.True(t, nextCalled)
	})

	t.Run("no response", func(t *testing.T) {
		next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			return &HandlerResult{Send: false}, nil
		}

		result, err := middleware(context.Background(), clientCtx, req, next)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.False(t, result.Send)
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	// Create rate limiter: 20 requests per second, burst of 2 (faster refill)
	middleware := RateLimitMiddleware(20, 2)

	clientCtx := &ClientContext{
		RequestID: 123,
		Addr:      &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
	}

	req := &packet.Packet{
		Code:       packet.CodeAccessRequest,
		Identifier: 1,
	}

	next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{Send: true}, nil
	}

	t.Run("first two requests allowed", func(t *testing.T) {
		// First request
		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Second request (should still be allowed due to burst)
		result, err = middleware(context.Background(), clientCtx, req, next)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("third request rate limited", func(t *testing.T) {
		// Third request should be rate limited
		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.Error(t, err)
		assert.Nil(t, result)

		handlerErr, ok := err.(*HandlerError)
		require.True(t, ok)
		assert.Equal(t, ErrorCodeRateLimited, handlerErr.Code)
		assert.Contains(t, handlerErr.Message, "rate limit exceeded")
	})

	t.Run("different client not affected", func(t *testing.T) {
		differentClientCtx := &ClientContext{
			RequestID: 124,
			Addr:      &net.UDPAddr{IP: net.ParseIP("192.168.1.101"), Port: 12345},
		}

		// Different client should not be rate limited
		result, err := middleware(context.Background(), differentClientCtx, req, next)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("tokens refill over time", func(t *testing.T) {
		// Wait for tokens to refill (at 2 per second, should get 1 token after 0.5 seconds)
		time.Sleep(50 * time.Millisecond) // Reduced from 600ms to 50ms

		// Should now be allowed again
		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})
}

func TestAuthenticationMiddleware(t *testing.T) {
	middleware := AuthenticationMiddleware()

	clientCtx := &ClientContext{
		RequestID: 123,
		Addr:      &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
	}

	next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{Send: true}, nil
	}

	t.Run("non-auth request passes through", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccountingRequest,
			Identifier: 1,
		}

		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("auth request without username rejected", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Attributes: []packet.Attribute{},
		}

		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Send)
		assert.Equal(t, packet.CodeAccessReject, result.Response.Code)

		// Check for Reply-Message
		replyAttr, found := result.Response.GetAttribute(packet.AttrReplyMessage)
		require.True(t, found)
		assert.Contains(t, replyAttr.GetString(), "Authentication is not supported")
	})

	t.Run("all auth requests rejected", func(t *testing.T) {
		testCases := []struct {
			name string
			req  *packet.Packet
		}{
			{
				name: "request without credentials",
				req: &packet.Packet{
					Code:       packet.CodeAccessRequest,
					Identifier: 1,
					Attributes: []packet.Attribute{
						packet.NewStringAttribute(packet.AttrUserName, "testuser"),
					},
				},
			},
			{
				name: "request with password",
				req: &packet.Packet{
					Code:       packet.CodeAccessRequest,
					Identifier: 1,
					Attributes: []packet.Attribute{
						packet.NewStringAttribute(packet.AttrUserName, "testuser"),
						packet.NewStringAttribute(packet.AttrUserPassword, "password"),
					},
				},
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result, err := middleware(context.Background(), clientCtx, tc.req, next)
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.True(t, result.Send)
				assert.Equal(t, packet.CodeAccessReject, result.Response.Code)

				// Check for Reply-Message
				replyAttr, found := result.Response.GetAttribute(packet.AttrReplyMessage)
				require.True(t, found)
				assert.Contains(t, replyAttr.GetString(), "Authentication is not supported")
			})
		}
	})

}

func TestSecurityMiddleware(t *testing.T) {
	middleware := SecurityMiddleware()

	clientCtx := &ClientContext{
		RequestID:    123,
		Addr:         &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
		SharedSecret: []byte("test-secret"),
	}

	next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{Send: true}, nil
	}

	t.Run("valid packet structure", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Length:     packet.PacketHeaderLength,
			Attributes: []packet.Attribute{},
		}

		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.NoError(t, err)
		assert.NotNil(t, result)
	})

	t.Run("packet too short", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Length:     10, // Too short
			Attributes: []packet.Attribute{},
		}

		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.Error(t, err)
		assert.Nil(t, result)

		handlerErr, ok := err.(*HandlerError)
		require.True(t, ok)
		assert.Equal(t, ErrorCodeInvalidRequest, handlerErr.Code)
	})

	t.Run("packet too long", func(t *testing.T) {
		req := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Identifier: 1,
			Length:     5000, // Too long
			Attributes: []packet.Attribute{},
		}

		result, err := middleware(context.Background(), clientCtx, req, next)
		assert.Error(t, err)
		assert.Nil(t, result)

		handlerErr, ok := err.(*HandlerError)
		require.True(t, ok)
		assert.Equal(t, ErrorCodeInvalidRequest, handlerErr.Code)
	})
}

func TestMetricsMiddleware(t *testing.T) {
	middleware := MetricsMiddleware()

	clientCtx := &ClientContext{
		RequestID:  123,
		Addr:       &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
		Attributes: make(map[string]interface{}),
	}

	req := &packet.Packet{
		Code:       packet.CodeAccessRequest,
		Identifier: 1,
	}

	t.Run("successful request metrics", func(t *testing.T) {
		next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			// Simulate some processing time
			time.Sleep(1 * time.Millisecond)
			return &HandlerResult{
				Response: &packet.Packet{Code: packet.CodeAccessAccept},
				Send:     true,
			}, nil
		}

		result, err := middleware(context.Background(), clientCtx, req, next)

		assert.NoError(t, err)
		assert.NotNil(t, result)

		// Check metrics were recorded
		assert.Contains(t, clientCtx.Attributes, "processing_time")
		assert.Contains(t, clientCtx.Attributes, "request_code")
		assert.Contains(t, clientCtx.Attributes, "response_code")

		processingTime, ok := clientCtx.Attributes["processing_time"].(time.Duration)
		require.True(t, ok)
		assert.Greater(t, processingTime, 500*time.Microsecond)

		assert.Equal(t, packet.CodeAccessRequest, clientCtx.Attributes["request_code"])
		assert.Equal(t, packet.CodeAccessAccept, clientCtx.Attributes["response_code"])
	})

	t.Run("failed request metrics", func(t *testing.T) {
		next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			return nil, assert.AnError
		}

		result, err := middleware(context.Background(), clientCtx, req, next)

		assert.Error(t, err)
		assert.Nil(t, result)

		// Check error was recorded
		assert.Contains(t, clientCtx.Attributes, "error")
		assert.Equal(t, assert.AnError.Error(), clientCtx.Attributes["error"])
	})
}

func TestRecoveryMiddleware(t *testing.T) {
	logger := log.NewDefaultLogger()
	middleware := RecoveryMiddleware(logger)

	clientCtx := &ClientContext{
		RequestID: 123,
		Addr:      &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 12345},
	}

	req := &packet.Packet{
		Code:       packet.CodeAccessRequest,
		Identifier: 1,
	}

	t.Run("normal execution", func(t *testing.T) {
		next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			return &HandlerResult{Send: true}, nil
		}

		result, err := middleware(context.Background(), clientCtx, req, next)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.True(t, result.Send)
	})

	t.Run("panic recovery", func(t *testing.T) {
		next := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
			panic("test panic")
		}

		result, err := middleware(context.Background(), clientCtx, req, next)

		assert.Error(t, err)
		assert.NotNil(t, result)

		// Should have created error response
		assert.True(t, result.Send)
		assert.Equal(t, packet.CodeAccessReject, result.Response.Code)
		assert.NotNil(t, result.Error)

		// Check error details
		handlerErr, ok := err.(*HandlerError)
		require.True(t, ok)
		assert.Equal(t, ErrorCodeInternalError, handlerErr.Code)
		assert.Contains(t, handlerErr.Message, "panic recovered")

		// Check Reply-Message
		replyAttr, found := result.Response.GetAttribute(packet.AttrReplyMessage)
		require.True(t, found)
		assert.Equal(t, "Internal server error", replyAttr.GetString())
	})
}

func TestValidationHelpers(t *testing.T) {
	t.Run("validatePacketStructure", func(t *testing.T) {
		// Valid packet
		validReq := &packet.Packet{
			Code:       packet.CodeAccessRequest,
			Length:     packet.PacketHeaderLength,
			Attributes: []packet.Attribute{},
		}
		err := validatePacketStructure(validReq)
		assert.NoError(t, err)

		// Packet too short
		shortReq := &packet.Packet{
			Code:   packet.CodeAccessRequest,
			Length: 10,
		}
		err = validatePacketStructure(shortReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too short")

		// Packet too long
		longReq := &packet.Packet{
			Code:   packet.CodeAccessRequest,
			Length: 5000,
		}
		err = validatePacketStructure(longReq)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too long")
	})

	t.Run("validateResponseAuthenticator", func(t *testing.T) {
		// Valid authenticator with valid shared secret
		var validAuth [16]byte
		validReq := &packet.Packet{
			Authenticator: validAuth,
		}
		err := validateResponseAuthenticator(validReq, []byte("secret"))
		assert.NoError(t, err)

		// Invalid case: empty shared secret
		err = validateResponseAuthenticator(validReq, []byte{})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "shared secret cannot be empty")
	})

	t.Run("validateMessageAuthenticator", func(t *testing.T) {
		// Create a test packet
		testPacket := packet.New(packet.CodeAccessRequest, 123)
		testPacket.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		// Encode the packet and add proper Message-Authenticator
		rawPacket, err := testPacket.Encode()
		assert.NoError(t, err)

		// Use crypto handler to add proper Message-Authenticator
		handler := crypto.NewMessageAuthenticatorHandler([]byte("secret"))
		signedPacket, err := handler.SignPacket(rawPacket)
		assert.NoError(t, err)

		// Decode the signed packet back
		decodedPacket, err := packet.Decode(signedPacket)
		assert.NoError(t, err)

		// Get the Message-Authenticator attribute
		msgAuthAttr, found := decodedPacket.GetAttribute(packet.AttrMessageAuthenticator)
		assert.True(t, found)

		// Validate Message-Authenticator
		err = validateMessageAuthenticator(decodedPacket, msgAuthAttr, []byte("secret"))
		assert.NoError(t, err)

		// Invalid Message-Authenticator length
		testPacket2 := packet.New(packet.CodeAccessRequest, 124)
		testPacket2.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		invalidAttr := packet.NewAttribute(packet.AttrMessageAuthenticator, make([]byte, 8))
		testPacket2.AddAttribute(invalidAttr)
		err = validateMessageAuthenticator(testPacket2, invalidAttr, []byte("secret"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid Message-Authenticator length")
	})
}
