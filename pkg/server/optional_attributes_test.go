package server

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/packet"
)

func TestOptionalAttributeValidator_ValidateOptionalAttributes(t *testing.T) {
	// Create a test dictionary with optional attributes
	dict := dictionary.NewDictionary()

	// Add a standard optional attribute
	dict.Attributes[100] = &dictionary.AttributeDefinition{
		Name:     "Test-Optional-String",
		ID:       100,
		DataType: dictionary.DataTypeString,
		Optional: true,
		Length:   10,
	}

	// Add a non-optional attribute
	dict.Attributes[101] = &dictionary.AttributeDefinition{
		Name:     "Test-Required-Integer",
		ID:       101,
		DataType: dictionary.DataTypeInteger,
		Optional: false,
	}

	tests := []struct {
		name          string
		strict        bool
		setupPacket   func() *packet.Packet
		expectError   bool
		errorContains string
	}{
		{
			name:   "valid optional attribute",
			strict: false,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.Attribute{
					Type:   100,
					Length: 12,                      // 2 bytes header + 10 bytes value
					Value:  []byte("test12345\x00"), // 10 bytes with null terminator
				})
				return pkt
			},
			expectError: false,
		},
		{
			name:   "optional attribute with wrong length",
			strict: false,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.Attribute{
					Type:   100,
					Length: 8,              // Wrong length
					Value:  []byte("test"), // 4 bytes instead of 10
				})
				return pkt
			},
			expectError:   true,
			errorContains: "optional attribute length mismatch",
		},
		{
			name:   "unknown attribute in non-strict mode",
			strict: false,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.Attribute{
					Type:   200, // Unknown attribute
					Length: 6,
					Value:  []byte("test"),
				})
				return pkt
			},
			expectError: false,
		},
		{
			name:   "unknown attribute in strict mode",
			strict: true,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.Attribute{
					Type:   200, // Unknown attribute
					Length: 6,
					Value:  []byte("test"),
				})
				return pkt
			},
			expectError:   true,
			errorContains: "unknown attribute type 200 not allowed in strict mode",
		},
		{
			name:   "non-optional attribute passes validation",
			strict: false,
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.Attribute{
					Type:   101, // Non-optional attribute
					Length: 6,
					Value:  []byte{0, 0, 0, 42}, // 4-byte integer
				})
				return pkt
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			options := &OptionalAttributeOptions{
				Dictionary: dict,
				Strict:     tt.strict,
			}
			validator := NewOptionalAttributeValidator(options)
			pkt := tt.setupPacket()

			err := validator.ValidateOptionalAttributes(context.Background(), pkt)

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

func TestOptionalAttributeValidator_ValidateDataTypes(t *testing.T) {
	dict := dictionary.NewDictionary()

	// Add optional attributes with different data types
	dict.Attributes[100] = &dictionary.AttributeDefinition{
		Name:     "Test-Optional-String",
		ID:       100,
		DataType: dictionary.DataTypeString,
		Optional: true,
	}

	dict.Attributes[101] = &dictionary.AttributeDefinition{
		Name:     "Test-Optional-Integer",
		ID:       101,
		DataType: dictionary.DataTypeInteger,
		Optional: true,
	}

	dict.Attributes[102] = &dictionary.AttributeDefinition{
		Name:     "Test-Optional-IPAddr",
		ID:       102,
		DataType: dictionary.DataTypeIPAddr,
		Optional: true,
	}

	tests := []struct {
		name          string
		attrType      uint8
		value         []byte
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid string attribute",
			attrType:    100,
			value:       []byte("test string"),
			expectError: false,
		},
		{
			name:          "invalid UTF-8 string",
			attrType:      100,
			value:         []byte{0xFF, 0xFE, 0xFD}, // Invalid UTF-8
			expectError:   true,
			errorContains: "invalid UTF-8",
		},
		{
			name:        "valid integer attribute",
			attrType:    101,
			value:       []byte{0, 0, 0, 42},
			expectError: false,
		},
		{
			name:          "invalid integer length",
			attrType:      101,
			value:         []byte{0, 0, 42}, // 3 bytes instead of 4
			expectError:   true,
			errorContains: "must be 4 bytes",
		},
		{
			name:        "valid IP address",
			attrType:    102,
			value:       []byte{192, 168, 1, 1},
			expectError: false,
		},
		{
			name:          "invalid IP address length",
			attrType:      102,
			value:         []byte{192, 168, 1}, // 3 bytes instead of 4
			expectError:   true,
			errorContains: "must be 4 bytes",
		},
	}

	options := &OptionalAttributeOptions{
		Dictionary: dict,
		Strict:     false,
	}
	validator := NewOptionalAttributeValidator(options)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := packet.New(packet.CodeAccessRequest, 1)
			pkt.AddAttribute(packet.Attribute{
				Type:   uint8(tt.attrType),
				Length: uint8(len(tt.value) + 2),
				Value:  tt.value,
			})

			err := validator.ValidateOptionalAttributes(context.Background(), pkt)

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

func TestOptionalAttributeMiddleware(t *testing.T) {
	dict := dictionary.NewDictionary()
	dict.Attributes[100] = &dictionary.AttributeDefinition{
		Name:     "Test-Optional",
		ID:       100,
		DataType: dictionary.DataTypeString,
		Optional: true,
		Length:   4,
	}

	options := &OptionalAttributeOptions{
		Dictionary: dict,
		Strict:     true,
	}

	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: []byte("testing123"),
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
		setupPacket func() *packet.Packet
		expectError bool
		errorCode   HandlerErrorCode
	}{
		{
			name: "valid optional attribute",
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.Attribute{
					Type:   100,
					Length: 6,
					Value:  []byte("test"),
				})
				return pkt
			},
			expectError: false,
		},
		{
			name: "invalid optional attribute",
			setupPacket: func() *packet.Packet {
				pkt := packet.New(packet.CodeAccessRequest, 1)
				pkt.AddAttribute(packet.Attribute{
					Type:   100,
					Length: 8,
					Value:  []byte("toolong"), // Wrong length
				})
				return pkt
			},
			expectError: true,
			errorCode:   ErrorCodeInvalidRequest,
		},
	}

	middleware := OptionalAttributeMiddleware(options)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
			}
		})
	}
}

func TestOptionalAttributeProcessor(t *testing.T) {
	dict := dictionary.NewDictionary()
	dict.Attributes[100] = &dictionary.AttributeDefinition{
		Name:     "Test-Optional",
		ID:       100,
		DataType: dictionary.DataTypeString,
		Optional: true,
	}

	processor := NewOptionalAttributeProcessor(dict)

	// Register a test processor
	var processedAttribute *packet.Attribute
	processor.RegisterProcessor(100, func(_ context.Context, attr packet.Attribute, _ *ClientContext) error {
		processedAttribute = &attr
		return nil
	})

	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: []byte("testing123"),
		Transport:    "udp",
	}

	pkt := packet.New(packet.CodeAccessRequest, 1)
	testAttr := packet.Attribute{
		Type:   100,
		Length: 6,
		Value:  []byte("test"),
	}
	pkt.AddAttribute(testAttr)

	err := processor.ProcessOptionalAttributes(context.Background(), pkt, clientCtx)

	assert.NoError(t, err)
	assert.NotNil(t, processedAttribute)
	assert.Equal(t, testAttr.Type, processedAttribute.Type)
	assert.Equal(t, testAttr.Value, processedAttribute.Value)
}

func TestOptionalAttributeProcessingMiddleware(t *testing.T) {
	dict := dictionary.NewDictionary()
	dict.Attributes[100] = &dictionary.AttributeDefinition{
		Name:     "Test-Optional",
		ID:       100,
		DataType: dictionary.DataTypeString,
		Optional: true,
	}

	processor := NewOptionalAttributeProcessor(dict)

	// Register a processor that adds context
	processor.RegisterProcessor(100, func(_ context.Context, _ packet.Attribute, clientCtx *ClientContext) error {
		// Add some processing context
		if clientCtx.Attributes == nil {
			clientCtx.Attributes = make(map[string]interface{})
		}
		clientCtx.Attributes["processed_optional"] = true
		return nil
	})

	clientCtx := &ClientContext{
		RemoteAddr:   &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 1812},
		SharedSecret: []byte("testing123"),
		Transport:    "udp",
	}

	// Mock handler that checks the context
	mockHandler := func(_ context.Context, clientCtx *ClientContext, _ *packet.Packet) (*HandlerResult, error) {
		// Verify that processing occurred
		if clientCtx.Attributes != nil {
			if processed, exists := clientCtx.Attributes["processed_optional"]; exists && processed.(bool) {
				return &HandlerResult{
					Response: &packet.Packet{Code: packet.CodeAccessAccept},
					Send:     true,
				}, nil
			}
		}
		return &HandlerResult{
			Response: &packet.Packet{Code: packet.CodeAccessReject},
			Send:     true,
		}, nil
	}

	middleware := OptionalAttributeProcessingMiddleware(processor)

	pkt := packet.New(packet.CodeAccessRequest, 1)
	pkt.AddAttribute(packet.Attribute{
		Type:   100,
		Length: 6,
		Value:  []byte("test"),
	})

	result, err := middleware(context.Background(), clientCtx, pkt, mockHandler)

	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, packet.CodeAccessAccept, result.Response.Code)
}

func TestIsValidUTF8(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid ASCII",
			data:     []byte("hello world"),
			expected: true,
		},
		{
			name:     "valid UTF-8",
			data:     []byte("hello 世界"),
			expected: true,
		},
		{
			name:     "invalid UTF-8",
			data:     []byte{0xFF, 0xFE, 0xFD},
			expected: false,
		},
		{
			name:     "empty string",
			data:     []byte{},
			expected: true,
		},
		{
			name:     "null byte",
			data:     []byte{0},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidUTF8(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestDecodeRune(t *testing.T) {
	tests := []struct {
		name         string
		data         []byte
		expectedRune rune
		expectedSize int
	}{
		{
			name:         "ASCII character",
			data:         []byte("A"),
			expectedRune: 'A',
			expectedSize: 1,
		},
		{
			name:         "2-byte UTF-8",
			data:         []byte("ñ"),
			expectedRune: 'ñ',
			expectedSize: 2,
		},
		{
			name:         "empty data",
			data:         []byte{},
			expectedRune: 0xFFFD,
			expectedSize: 1,
		},
		{
			name:         "invalid UTF-8",
			data:         []byte{0xFF},
			expectedRune: 0xFFFD,
			expectedSize: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, size := decodeRune(tt.data)
			assert.Equal(t, tt.expectedRune, r)
			assert.Equal(t, tt.expectedSize, size)
		})
	}
}
