package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/vitalvas/goradius/pkg/packet"
)

func TestEnhancedClientValidator_ValidateBasic(t *testing.T) {
	config := DefaultClientValidationConfig()
	config.RequireSharedSecret = true
	config.MinSharedSecretLength = 8
	config.AllowedNASIPAddresses = []net.IP{net.ParseIP("192.168.1.100")}

	validator := NewEnhancedClientValidator(config)
	defer validator.Close()

	tests := []struct {
		name          string
		setupClient   func() *ClientContext
		setupPacket   func() *packet.Packet
		expectError   bool
		errorContains string
	}{
		{
			name: "valid basic validation",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				return packet.New(packet.CodeAccessRequest, 1)
			},
			expectError: false,
		},
		{
			name: "missing shared secret",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 1812},
					SharedSecret: nil,
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				return packet.New(packet.CodeAccessRequest, 1)
			},
			expectError:   true,
			errorContains: "shared secret is required",
		},
		{
			name: "shared secret too short",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.1.100"), Port: 1812},
					SharedSecret: []byte("short"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				return packet.New(packet.CodeAccessRequest, 1)
			},
			expectError:   true,
			errorContains: "shared secret length",
		},
		{
			name: "client IP not allowed",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("192.168.1.200"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				return packet.New(packet.CodeAccessRequest, 1)
			},
			expectError:   true,
			errorContains: "not in allowed list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientCtx := tt.setupClient()
			pkt := tt.setupPacket()

			err := validator.ValidateClient(context.Background(), clientCtx, pkt)

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

func TestEnhancedClientValidator_ValidateStrict(t *testing.T) {
	config := DefaultClientValidationConfig()
	config.Level = ClientValidationStrict
	config.RequiredNASIdentifier = true
	config.AllowedNASIdentifiers = []string{"nas1.example.com", "nas2.example.com"}
	config.RequireCallingStationID = true

	validator := NewEnhancedClientValidator(config)
	defer validator.Close()

	tests := []struct {
		name          string
		setupClient   func() *ClientContext
		setupPacket   func() *packet.Packet
		expectError   bool
		errorContains string
	}{
		{
			name: "valid strict validation",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrNASIdentifier, "nas1.example.com"))
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrCallingStationID, "user@example.com"))
				return pkt
			},
			expectError: false,
		},
		{
			name: "missing required NAS-Identifier",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrCallingStationID, "user@example.com"))
				return pkt
			},
			expectError:   true,
			errorContains: "NAS-Identifier is required",
		},
		{
			name: "invalid NAS-Identifier",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrNASIdentifier, "invalid.example.com"))
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrCallingStationID, "user@example.com"))
				return pkt
			},
			expectError:   true,
			errorContains: "NAS-Identifier invalid.example.com is not allowed",
		},
		{
			name: "valid packet with all required attributes",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrNASIdentifier, "nas1.example.com"))
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrCallingStationID, "user@example.com"))
				return pkt
			},
			expectError: false,
		},
		{
			name: "missing required Calling-Station-Id",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrNASIdentifier, "nas1.example.com"))
				return pkt
			},
			expectError:   true,
			errorContains: "Calling-Station-Id is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientCtx := tt.setupClient()
			pkt := tt.setupPacket()

			err := validator.ValidateClient(context.Background(), clientCtx, pkt)

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

func TestEnhancedClientValidator_ValidateParanoid(t *testing.T) {
	config := DefaultClientValidationConfig()
	config.Level = ClientValidationParanoid
	config.ValidateAcctSessionID = true

	validator := NewEnhancedClientValidator(config)
	defer validator.Close()

	tests := []struct {
		name          string
		setupClient   func() *ClientContext
		setupPacket   func() *packet.Packet
		expectError   bool
		errorContains string
	}{
		{
			name: "valid accounting request",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccountingRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrAcctSessionID, "session123456789"))
				ip := net.ParseIP("127.0.0.1").To4()
				pkt.AddAttribute(packet.NewIPAddressAttribute(packet.AttrNASIPAddress, [4]byte{ip[0], ip[1], ip[2], ip[3]}))
				return pkt
			},
			expectError: false,
		},
		{
			name: "missing Acct-Session-Id",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				return packet.New(packet.CodeAccountingRequest, 1)
			},
			expectError:   true,
			errorContains: "Acct-Session-Id is required",
		},
		{
			name: "invalid Acct-Session-Id length",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccountingRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrAcctSessionID, "short")) // Too short
				return pkt
			},
			expectError:   true,
			errorContains: "Acct-Session-Id length",
		},
		{
			name: "invalid Acct-Session-Id characters",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccountingRequest, 1)
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrAcctSessionID, "session\x00\r\n")) // Invalid characters
				return pkt
			},
			expectError:   true,
			errorContains: "invalid characters",
		},
		{
			name: "NAS-IP-Address mismatch",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				ip := net.ParseIP("192.168.1.1").To4()
				pkt.AddAttribute(packet.NewIPAddressAttribute(packet.AttrNASIPAddress, [4]byte{ip[0], ip[1], ip[2], ip[3]})) // Different from client IP
				return pkt
			},
			expectError:   true,
			errorContains: "does not match client IP",
		},
		{
			name: "invalid User-Name length",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("secretpassword"),
					Transport:    "udp",
				}
			},
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				// Create a user name that's too long (> 253 characters)
				longUserName := make([]byte, 254)
				for i := range longUserName {
					longUserName[i] = 'a'
				}
				pkt.AddAttribute(packet.NewStringAttribute(packet.AttrUserName, string(longUserName)))
				return pkt
			},
			expectError:   true,
			errorContains: "User-Name length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clientCtx := tt.setupClient()
			pkt := tt.setupPacket()

			err := validator.ValidateClient(context.Background(), clientCtx, pkt)

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

func TestEnhancedClientValidator_SessionManagement(t *testing.T) {
	config := DefaultClientValidationConfig()
	config.SessionTimeout = time.Millisecond * 100 // Short timeout for testing

	validator := NewEnhancedClientValidator(config)

	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: []byte("secretpassword"),
		Transport:    "udp",
	}

	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.NewStringAttribute(packet.AttrNASIdentifier, "test-nas"))

	// First request should create session
	err := validator.ValidateClient(context.Background(), clientCtx, pkt)
	assert.NoError(t, err)

	// Check session exists
	session, exists := validator.GetClientSession("127.0.0.1")
	assert.True(t, exists)
	assert.NotNil(t, session)
	assert.Equal(t, int64(1), session.RequestCount)
	assert.Equal(t, "test-nas", session.NASIdentifier)

	// Second request should update session
	err = validator.ValidateClient(context.Background(), clientCtx, pkt)
	assert.NoError(t, err)

	session, exists = validator.GetClientSession("127.0.0.1")
	assert.True(t, exists)
	assert.Equal(t, int64(2), session.RequestCount)

	// Wait for session to expire
	time.Sleep(time.Millisecond * 200)

	// Clean up the validator
	defer validator.Close()
}

func TestClientRateLimiter(t *testing.T) {
	rateLimiter := NewClientRateLimiter(5) // 5 requests per second
	defer rateLimiter.Close()

	clientID := "test-client"

	// Should allow up to 5 requests
	for i := 0; i < 5; i++ {
		allowed := rateLimiter.Allow(clientID)
		assert.True(t, allowed, "request %d should be allowed", i+1)
	}

	// 6th request should be denied
	allowed := rateLimiter.Allow(clientID)
	assert.False(t, allowed, "6th request should be denied")

	// After waiting, should allow requests again
	time.Sleep(time.Second + time.Millisecond*100)
	allowed = rateLimiter.Allow(clientID)
	assert.True(t, allowed, "request after window should be allowed")
}

func TestEnhancedClientValidationMiddleware(t *testing.T) {
	config := DefaultClientValidationConfig()
	config.RequireSharedSecret = true
	config.MinSharedSecretLength = 8

	validator := NewEnhancedClientValidator(config)
	defer validator.Close()
	middleware := EnhancedClientValidationMiddleware(validator)

	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: []byte("secretpassword"),
		Transport:    "udp",
	}

	// Mock handler
	mockHandler := func(_ context.Context, _ *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		return &HandlerResult{
			Response: &packet.Packet{Code: packet.CodeAccessAccept},
			Send:     true,
		}, nil
	}

	tests := []struct {
		name        string
		setupClient func() *ClientContext
		expectError bool
		errorCode   HandlerErrorCode
	}{
		{
			name: "valid client",
			setupClient: func() *ClientContext {
				return clientCtx
			},
			expectError: false,
		},
		{
			name: "invalid client",
			setupClient: func() *ClientContext {
				return &ClientContext{
					RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
					SharedSecret: []byte("short"), // Too short
					Transport:    "udp",
				}
			},
			expectError: true,
			errorCode:   ErrorCodeSecurityViolation,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := packet.New(packet.CodeAccessRequest, 1)
			clientCtx := tt.setupClient()

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
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
	tests := []struct {
		name     string
		addr     net.Addr
		expected string
	}{
		{
			name:     "UDP address",
			addr:     &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 1812},
			expected: "192.168.1.1",
		},
		{
			name:     "TCP address",
			addr:     &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 1812},
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := getClientIP(tt.addr)
			assert.Equal(t, tt.expected, ip.String())
		})
	}
}

func TestConstantTimeCompare(t *testing.T) {
	secret1 := []byte("secret123")
	secret2 := []byte("secret123")
	secret3 := []byte("different")

	// Same secrets should return true
	assert.True(t, constantTimeCompare(secret1, secret2))

	// Different secrets should return false
	assert.False(t, constantTimeCompare(secret1, secret3))

	// Different lengths should return false
	assert.False(t, constantTimeCompare(secret1, []byte("short")))
}
