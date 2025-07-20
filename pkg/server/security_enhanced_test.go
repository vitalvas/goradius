package server

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vitalvas/goradius/pkg/packet"
)

func TestEnhancedSecurityValidator_ValidatePacket(t *testing.T) {
	sharedSecret := []byte("testing123")
	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: sharedSecret,
		Transport:    "udp",
	}

	tests := []struct {
		name          string
		options       *EnhancedSecurityOptions
		setupPacket   func() *packet.Packet
		expectError   bool
		errorContains string
	}{
		{
			name:    "valid packet with default options",
			options: DefaultEnhancedSecurityOptions(),
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50
				return pkt
			},
			expectError: false,
		},
		{
			name: "packet too large",
			options: &EnhancedSecurityOptions{
				MaxPacketSize: 20,
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50
				return pkt
			},
			expectError:   true,
			errorContains: "packet size 50 exceeds maximum",
		},
		{
			name: "unauthorized packet type",
			options: &EnhancedSecurityOptions{
				AllowedPacketTypes: []packet.Code{packet.CodeAccessRequest},
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccountingRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50
				return pkt
			},
			expectError:   true,
			errorContains: "packet type 4 not allowed",
		},
		{
			name: "weak authenticator",
			options: &EnhancedSecurityOptions{
				ValidatePacketAuth: true,
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0} // All zeros
				pkt.Length = 50
				return pkt
			},
			expectError:   true,
			errorContains: "Request Authenticator appears to be weak",
		},
		{
			name: "Message-Authenticator required but not present",
			options: &EnhancedSecurityOptions{
				RequireMessageAuth: true,
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50
				return pkt
			},
			expectError:   true,
			errorContains: "Message-Authenticator is required but not present",
		},
		{
			name: "Message-Authenticator present with valid length",
			options: &EnhancedSecurityOptions{
				ValidateMessageAuth: true,
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50

				// Add Message-Authenticator attribute
				msgAuthAttr := packet.Attribute{
					Type:   packet.AttrMessageAuthenticator,
					Length: 18, // 2 bytes header + 16 bytes value
					Value:  make([]byte, 16),
				}
				pkt.AddAttribute(msgAuthAttr)

				return pkt
			},
			expectError: false,
		},
		{
			name: "Message-Authenticator present with invalid length",
			options: &EnhancedSecurityOptions{
				ValidateMessageAuth: true,
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50

				// Add Message-Authenticator attribute with invalid length
				msgAuthAttr := packet.Attribute{
					Type:   packet.AttrMessageAuthenticator,
					Length: 10,              // Invalid length
					Value:  make([]byte, 8), // Invalid value length
				}
				pkt.AddAttribute(msgAuthAttr)

				return pkt
			},
			expectError:   true,
			errorContains: "invalid Message-Authenticator length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewEnhancedSecurityValidator(tt.options)
			pkt := tt.setupPacket()

			err := validator.ValidatePacket(context.Background(), clientCtx, pkt)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestEnhancedSecurityMiddleware(t *testing.T) {
	sharedSecret := []byte("testing123")
	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: sharedSecret,
		Transport:    "udp",
	}

	// Mock handler that always returns success
	mockHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{
			Response: &packet.Packet{Code: packet.CodeAccessAccept},
			Send:     true,
		}, nil
	}

	tests := []struct {
		name        string
		options     *EnhancedSecurityOptions
		setupPacket func() *packet.Packet
		expectError bool
		errorCode   HandlerErrorCode
	}{
		{
			name:    "valid packet passes through",
			options: DefaultEnhancedSecurityOptions(),
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50
				return pkt
			},
			expectError: false,
		},
		{
			name: "invalid packet blocked",
			options: &EnhancedSecurityOptions{
				MaxPacketSize: 20,
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				pkt.Length = 50
				return pkt
			},
			expectError: true,
			errorCode:   ErrorCodeSecurityViolation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := EnhancedSecurityMiddleware(tt.options)
			pkt := tt.setupPacket()

			result, err := middleware(context.Background(), clientCtx, pkt, mockHandler)

			if tt.expectError {
				assert.Error(t, err)
				if handlerErr, ok := err.(*HandlerError); ok {
					assert.Equal(t, tt.errorCode, handlerErr.Code)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, packet.CodeAccessAccept, result.Response.Code)
			}
		})
	}
}

func TestEnhancedMessageAuthenticatorMiddleware(t *testing.T) {
	sharedSecret := []byte("testing123")
	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: sharedSecret,
		Transport:    "udp",
	}

	// Mock handler that always returns success
	mockHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{
			Response: &packet.Packet{Code: packet.CodeAccessAccept},
			Send:     true,
		}, nil
	}

	tests := []struct {
		name          string
		required      bool
		setupPacket   func() *packet.Packet
		expectError   bool
		errorContains string
	}{
		{
			name:     "no Message-Authenticator, not required",
			required: false,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				return pkt
			},
			expectError: false,
		},
		{
			name:     "no Message-Authenticator, required",
			required: true,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				return pkt
			},
			expectError:   true,
			errorContains: "Message-Authenticator is required but not present",
		},
		{
			name:     "valid Message-Authenticator",
			required: true,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

				// Add Message-Authenticator attribute
				msgAuthAttr := packet.Attribute{
					Type:   packet.AttrMessageAuthenticator,
					Length: 18, // 2 bytes header + 16 bytes value
					Value:  make([]byte, 16),
				}
				pkt.AddAttribute(msgAuthAttr)

				return pkt
			},
			expectError: false,
		},
		{
			name:     "invalid Message-Authenticator length",
			required: true,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

				// Add Message-Authenticator attribute with invalid length
				msgAuthAttr := packet.Attribute{
					Type:   packet.AttrMessageAuthenticator,
					Length: 10,              // Invalid length
					Value:  make([]byte, 8), // Invalid value length
				}
				pkt.AddAttribute(msgAuthAttr)

				return pkt
			},
			expectError:   true,
			errorContains: "invalid Message-Authenticator length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := EnhancedMessageAuthenticatorMiddleware(tt.required)
			pkt := tt.setupPacket()

			result, err := middleware(context.Background(), clientCtx, pkt, mockHandler)

			if tt.expectError {
				assert.Error(t, err)
				if handlerErr, ok := err.(*HandlerError); ok {
					assert.Equal(t, ErrorCodeSecurityViolation, handlerErr.Code)
					if tt.errorContains != "" {
						assert.Contains(t, handlerErr.Message, tt.errorContains)
					}
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, packet.CodeAccessAccept, result.Response.Code)
			}
		})
	}
}

func TestEnhancedPacketAuthenticatorMiddleware(t *testing.T) {
	sharedSecret := []byte("testing123")
	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: sharedSecret,
		Transport:    "udp",
	}

	// Mock handler that always returns success
	mockHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{
			Response: &packet.Packet{Code: packet.CodeAccessAccept},
			Send:     true,
		}, nil
	}

	tests := []struct {
		name        string
		setupPacket func() *packet.Packet
		expectError bool
		errorCode   HandlerErrorCode
	}{
		{
			name: "valid Access-Request authenticator",
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				return pkt
			},
			expectError: false,
		},
		{
			name: "weak Access-Request authenticator",
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.Authenticator = [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
				return pkt
			},
			expectError: true,
			errorCode:   ErrorCodeSecurityViolation,
		},
		{
			name: "valid Accounting-Request authenticator",
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccountingRequest, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				return pkt
			},
			expectError: false,
		},
		{
			name: "non-request packet (no validation)",
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessAccept, 1)
				pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
				return pkt
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			middleware := EnhancedPacketAuthenticatorMiddleware()
			pkt := tt.setupPacket()

			result, err := middleware(context.Background(), clientCtx, pkt, mockHandler)

			if tt.expectError {
				assert.Error(t, err)
				if handlerErr, ok := err.(*HandlerError); ok {
					assert.Equal(t, tt.errorCode, handlerErr.Code)
				}
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, packet.CodeAccessAccept, result.Response.Code)
			}
		})
	}
}

func TestEnhancedSecurityEventLogger(t *testing.T) {
	logger := NewEnhancedSecurityEventLogger()

	// Test handler
	var receivedEvents []EnhancedSecurityEvent
	handler := EnhancedSecurityEventHandlerFunc(func(event EnhancedSecurityEvent) {
		receivedEvents = append(receivedEvents, event)
	})

	logger.AddHandler(handler)

	// Test logging
	logger.LogSecurityViolation(
		EnhancedSecurityEventInvalidAuthenticator,
		net.ParseIP("127.0.0.1"),
		"Test violation",
		packet.CodeAccessRequest,
		map[string]interface{}{"test": "value"},
	)

	assert.Len(t, receivedEvents, 1)
	event := receivedEvents[0]
	assert.Equal(t, EnhancedSecurityEventInvalidAuthenticator, event.Type)
	assert.Equal(t, net.ParseIP("127.0.0.1"), event.ClientIP)
	assert.Equal(t, "Test violation", event.Message)
	assert.Equal(t, packet.CodeAccessRequest, event.PacketCode)
	assert.Equal(t, "value", event.Context["test"])
	assert.WithinDuration(t, time.Now(), event.Timestamp, time.Second)
}

func TestEnhancedSecurityEventMiddleware(t *testing.T) {
	logger := NewEnhancedSecurityEventLogger()

	var receivedEvents []EnhancedSecurityEvent
	handler := EnhancedSecurityEventHandlerFunc(func(event EnhancedSecurityEvent) {
		receivedEvents = append(receivedEvents, event)
	})
	logger.AddHandler(handler)

	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: []byte("testing123"),
		Transport:    "udp",
	}

	// Handler that returns a security violation
	errorHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return nil, NewHandlerError(ErrorCodeSecurityViolation, "Test security violation", fmt.Errorf("test error"))
	}

	// Success handler
	successHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{
			Response: &packet.Packet{Code: packet.CodeAccessAccept},
			Send:     true,
		}, nil
	}

	middleware := EnhancedSecurityEventMiddleware(logger)

	t.Run("logs security violations", func(t *testing.T) {
		receivedEvents = nil // Reset

		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		pkt.Length = 50

		result, err := middleware(context.Background(), clientCtx, pkt, errorHandler)

		assert.Error(t, err)
		assert.Nil(t, result)
		assert.Len(t, receivedEvents, 1)

		event := receivedEvents[0]
		assert.Equal(t, EnhancedSecurityEventValidationError, event.Type)
		assert.Equal(t, net.ParseIP("127.0.0.1"), event.ClientIP)
		assert.Equal(t, "Test security violation", event.Message)
		assert.Equal(t, packet.CodeAccessRequest, event.PacketCode)
	})

	t.Run("does not log successful requests", func(t *testing.T) {
		receivedEvents = nil // Reset

		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
		pkt.Length = 50

		result, err := middleware(context.Background(), clientCtx, pkt, successHandler)

		assert.NoError(t, err)
		assert.NotNil(t, result)
		assert.Len(t, receivedEvents, 0)
	})
}

func TestMessageAuthenticatorHelper(t *testing.T) {
	sharedSecret := []byte("testing123")
	helper := NewMessageAuthenticatorHelper(sharedSecret)

	t.Run("validate existing Message-Authenticator", func(t *testing.T) {
		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		// Add Message-Authenticator attribute
		msgAuthAttr := packet.Attribute{
			Type:   packet.AttrMessageAuthenticator,
			Length: 18, // 2 bytes header + 16 bytes value
			Value:  make([]byte, 16),
		}
		pkt.AddAttribute(msgAuthAttr)

		err := helper.ValidateMessageAuthenticator(pkt)
		assert.NoError(t, err)
	})

	t.Run("validate non-existent Message-Authenticator", func(t *testing.T) {
		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		err := helper.ValidateMessageAuthenticator(pkt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Message-Authenticator attribute not found")
	})

	t.Run("validate Message-Authenticator with invalid length", func(t *testing.T) {
		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		// Add Message-Authenticator attribute with invalid length
		msgAuthAttr := packet.Attribute{
			Type:   packet.AttrMessageAuthenticator,
			Length: 10,              // Invalid length
			Value:  make([]byte, 8), // Invalid value length
		}
		pkt.AddAttribute(msgAuthAttr)

		err := helper.ValidateMessageAuthenticator(pkt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid Message-Authenticator length")
	})

	t.Run("add Message-Authenticator to packet", func(t *testing.T) {
		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		err := helper.AddMessageAuthenticator(pkt)
		assert.NoError(t, err)

		// Verify Message-Authenticator was added
		var found bool
		for _, attr := range pkt.Attributes {
			if attr.Type == packet.AttrMessageAuthenticator {
				found = true
				assert.Equal(t, uint8(18), attr.Length)
				assert.Len(t, attr.Value, 16)
				break
			}
		}
		assert.True(t, found)
	})

	t.Run("add Message-Authenticator to packet that already has one", func(t *testing.T) {
		pkt := packet.New(packet.CodeAccessRequest, 1)
		pkt.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

		// Add Message-Authenticator attribute
		msgAuthAttr := packet.Attribute{
			Type:   packet.AttrMessageAuthenticator,
			Length: 18, // 2 bytes header + 16 bytes value
			Value:  make([]byte, 16),
		}
		pkt.AddAttribute(msgAuthAttr)

		err := helper.AddMessageAuthenticator(pkt)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "Message-Authenticator already exists")
	})
}

func TestIsZeroOrRepeatedEnhanced(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "empty slice",
			data:     []byte{},
			expected: true,
		},
		{
			name:     "all zeros",
			data:     []byte{0, 0, 0, 0},
			expected: true,
		},
		{
			name:     "repeated non-zero",
			data:     []byte{1, 1, 1, 1},
			expected: true,
		},
		{
			name:     "mixed values",
			data:     []byte{1, 2, 3, 4},
			expected: false,
		},
		{
			name:     "single byte",
			data:     []byte{5},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isZeroOrRepeatedEnhanced(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEnhancedSecurityEventType_String(t *testing.T) {
	tests := []struct {
		eventType EnhancedSecurityEventType
		expected  string
	}{
		{EnhancedSecurityEventInvalidAuthenticator, "InvalidAuthenticator"},
		{EnhancedSecurityEventInvalidMessageAuth, "InvalidMessageAuth"},
		{EnhancedSecurityEventPacketTooLarge, "PacketTooLarge"},
		{EnhancedSecurityEventUnauthorizedPacketType, "UnauthorizedPacketType"},
		{EnhancedSecurityEventWeakAuthenticator, "WeakAuthenticator"},
		{EnhancedSecurityEventValidationError, "ValidationError"},
		{EnhancedSecurityEventType(999), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.eventType.String())
		})
	}
}
