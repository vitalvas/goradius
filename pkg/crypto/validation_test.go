package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketValidator_ValidatePacketStructure(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	testCases := []struct {
		name        string
		packetData  []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid minimum packet",
			packetData:  make([]byte, 20), // Minimum RADIUS packet size
			expectError: false,
		},
		{
			name:        "packet too short",
			packetData:  make([]byte, 19),
			expectError: true,
			errorMsg:    "packet too short",
		},
		{
			name:        "packet too large",
			packetData:  make([]byte, 4097),
			expectError: true,
			errorMsg:    "packet too large",
		},
		{
			name:        "valid maximum packet",
			packetData:  make([]byte, 4096),
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := pv.validatePacketStructure(tc.packetData)
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPacketValidator_ValidatePacketLength(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	testCases := []struct {
		name        string
		packetData  []byte
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid length",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x14, // Length: 20 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectError: false,
		},
		{
			name: "length mismatch - too short",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x20, // Length: 32 bytes (but packet is only 20)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectError: true,
			errorMsg:    "length mismatch",
		},
		{
			name: "length mismatch - too long",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x10, // Length: 16 bytes (but packet is 20)
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectError: true,
			errorMsg:    "length mismatch",
		},
		{
			name:        "packet too short for length field",
			packetData:  []byte{0x01, 0x00, 0x00}, // Only 3 bytes
			expectError: true,
			errorMsg:    "packet too short to contain length field",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := pv.validatePacketLength(tc.packetData)
			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.errorMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPacketValidator_ValidateAuthenticator(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	// Create a valid request authenticator
	requestAuth, err := GenerateRequestAuthenticator()
	require.NoError(t, err)

	testCases := []struct {
		name        string
		packetType  uint8
		identifier  uint8
		packetData  []byte
		requestAuth *Authenticator
		expectValid bool
		expectError bool
	}{
		{
			name:       "Access-Request with non-zero authenticator",
			packetType: 1,
			identifier: 1,
			packetData: func() []byte {
				data := make([]byte, 20)
				data[0] = 1  // Code
				data[1] = 1  // Identifier
				data[2] = 0  // Length high
				data[3] = 20 // Length low
				copy(data[4:], requestAuth[:])
				return data
			}(),
			expectValid: true,
			expectError: false,
		},
		{
			name:       "Access-Request with zero authenticator",
			packetType: 1,
			identifier: 1,
			packetData: func() []byte {
				data := make([]byte, 20)
				data[0] = 1  // Code
				data[1] = 1  // Identifier
				data[2] = 0  // Length high
				data[3] = 20 // Length low
				// Authenticator is already zeros
				return data
			}(),
			expectValid: false,
			expectError: true,
		},
		{
			name:        "Response packet without request authenticator",
			packetType:  2, // Access-Accept
			identifier:  1,
			packetData:  make([]byte, 20),
			requestAuth: nil,
			expectValid: false,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := pv.validateAuthenticator(tc.packetData, tc.packetType, tc.identifier, tc.requestAuth)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectValid, valid)
		})
	}
}

func TestPacketValidator_ValidateMessageAuthenticator(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	// Create a packet without Message-Authenticator
	basePacket := []byte{
		0x01, 0x00, // Code, Identifier
		0x00, 0x14, // Length: 20 bytes
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// Create a packet with valid Message-Authenticator
	packetWithMsgAuth, err := AddMessageAuthenticator(basePacket, sharedSecret)
	require.NoError(t, err)

	// Create a packet with invalid Message-Authenticator
	invalidMsgAuthPacket := make([]byte, len(packetWithMsgAuth))
	copy(invalidMsgAuthPacket, packetWithMsgAuth)
	// Corrupt the Message-Authenticator
	invalidMsgAuthPacket[len(invalidMsgAuthPacket)-1] ^= 0xFF

	testCases := []struct {
		name        string
		packetData  []byte
		expectValid bool
		expectError bool
	}{
		{
			name:        "packet without Message-Authenticator",
			packetData:  basePacket,
			expectValid: true, // Valid because no Message-Authenticator is present
			expectError: false,
		},
		{
			name:        "packet with valid Message-Authenticator",
			packetData:  packetWithMsgAuth,
			expectValid: true,
			expectError: false,
		},
		{
			name:        "packet with invalid Message-Authenticator",
			packetData:  invalidMsgAuthPacket,
			expectValid: false,
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := pv.validateMessageAuthenticator(tc.packetData)

			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectValid, valid)
		})
	}
}

func TestPacketValidator_ValidateAttributesStructure(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	testCases := []struct {
		name        string
		packetData  []byte
		expectValid bool
	}{
		{
			name: "valid attributes structure",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x20, // Length: 32 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Attributes
				0x01, 0x06, 0x74, 0x65, 0x73, 0x74, // User-Name = "test"
				0x02, 0x06, 0x70, 0x61, 0x73, 0x73, // User-Password = "pass"
			},
			expectValid: true,
		},
		{
			name: "attribute with zero length",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x18, // Length: 24 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Invalid attribute
				0x01, 0x00, 0x74, 0x65, // Length = 0 (invalid)
			},
			expectValid: false,
		},
		{
			name: "attribute extending beyond packet",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x18, // Length: 24 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Attribute claiming to be longer than packet
				0x01, 0x10, 0x74, 0x65, // Length = 16 but only 4 bytes available
			},
			expectValid: false,
		},
		{
			name: "truncated attribute header",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x16, // Length: 22 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// Incomplete attribute (only type, no length)
				0x01, 0x06,
			},
			expectValid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid := pv.validateAttributesStructure(tc.packetData)
			assert.Equal(t, tc.expectValid, valid)
		})
	}
}

func TestPacketValidator_IsEAPPacket(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	testCases := []struct {
		name       string
		packetData []byte
		expectEAP  bool
	}{
		{
			name: "packet with EAP-Message attribute",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x20, // Length: 32 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// EAP-Message attribute (type 79)
				0x4F, 0x06, 0x01, 0x02, 0x03, 0x04,
				// Additional attribute
				0x01, 0x06, 0x74, 0x65, 0x73, 0x74,
			},
			expectEAP: true,
		},
		{
			name: "packet without EAP-Message attribute",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x20, // Length: 32 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// User-Name attribute
				0x01, 0x06, 0x74, 0x65, 0x73, 0x74,
				// User-Password attribute
				0x02, 0x06, 0x70, 0x61, 0x73, 0x73,
			},
			expectEAP: false,
		},
		{
			name: "empty packet",
			packetData: []byte{
				0x01, 0x00, // Code, Identifier
				0x00, 0x14, // Length: 20 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
			expectEAP: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isEAP := pv.isEAPPacket(tc.packetData)
			assert.Equal(t, tc.expectEAP, isEAP)
		})
	}
}

func TestSecurityValidator_ValidateAuthentication(t *testing.T) {
	sharedSecret := []byte("secret123")
	sv := NewSecurityValidator(sharedSecret)

	// Create a valid PAP Access-Request packet
	packetData := []byte{
		0x01, 0x42, // Code: Access-Request, Identifier: 66
		0x00, 0x20, // Length: 32 bytes
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Request Authenticator
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// User-Name attribute
		0x01, 0x06, 0x74, 0x65, 0x73, 0x74,
		// User-Password attribute
		0x02, 0x06, 0x70, 0x61, 0x73, 0x73,
	}

	result, err := sv.ValidateAuthentication(packetData, 1, 0x42, nil, "PAP")
	require.NoError(t, err)
	assert.False(t, result.Valid)             // PAP is no longer supported
	assert.True(t, result.AuthenticatorValid) // But authenticator validation still works
	assert.True(t, result.MessageAuthValid)
	assert.True(t, result.IntegrityValid)
}

func TestSecurityValidator_ValidateStructure(t *testing.T) {
	sharedSecret := []byte("secret123")
	sv := NewSecurityValidator(sharedSecret)

	// Valid packet
	validPacket := []byte{
		0x01, 0x00, // Code, Identifier
		0x00, 0x14, // Length: 20 bytes
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// Invalid packet (too short)
	invalidPacket := []byte{0x01, 0x00}

	assert.NoError(t, sv.ValidateStructure(validPacket))
	assert.Error(t, sv.ValidateStructure(invalidPacket))
}

func TestPacketValidationError(t *testing.T) {
	err := &PacketValidationError{
		Type:    "Test",
		Message: "test error message",
	}

	assert.Equal(t, "Test validation error: test error message", err.Error())
}

func TestPacketValidator_HasAttribute(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	packetData := []byte{
		0x01, 0x00, // Code, Identifier
		0x00, 0x20, // Length: 32 bytes
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// User-Name attribute (type 1)
		0x01, 0x06, 0x74, 0x65, 0x73, 0x74,
		// User-Password attribute (type 2)
		0x02, 0x06, 0x70, 0x61, 0x73, 0x73,
	}

	assert.True(t, pv.hasAttribute(packetData, 1))  // User-Name exists
	assert.True(t, pv.hasAttribute(packetData, 2))  // User-Password exists
	assert.False(t, pv.hasAttribute(packetData, 3)) // CHAP-Password doesn't exist
}

func TestValidationResult(t *testing.T) {
	result := &ValidationResult{
		Valid:              false,
		Errors:             []PacketValidationError{{Type: "Test", Message: "error"}},
		AuthenticatorValid: true,
		MessageAuthValid:   false,
		IntegrityValid:     true,
	}

	assert.False(t, result.Valid)
	assert.Len(t, result.Errors, 1)
	assert.True(t, result.AuthenticatorValid)
	assert.False(t, result.MessageAuthValid)
	assert.True(t, result.IntegrityValid)
}

func TestPacketValidator_ValidatePacketIntegrity(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	// Valid packet with proper attribute structure
	validPacket := []byte{
		0x01, 0x00, // Code, Identifier
		0x00, 0x20, // Length: 32 bytes
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// User-Name attribute
		0x01, 0x06, 0x74, 0x65, 0x73, 0x74,
		// User-Password attribute
		0x02, 0x06, 0x70, 0x61, 0x73, 0x73,
	}

	// EAP packet without Message-Authenticator (invalid)
	invalidEAPPacket := []byte{
		0x01, 0x00, // Code, Identifier
		0x00, 0x1A, // Length: 26 bytes
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Authenticator
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		// EAP-Message attribute (type 79)
		0x4F, 0x06, 0x01, 0x02, 0x03, 0x04,
	}

	assert.True(t, pv.validatePacketIntegrity(validPacket, 1))
	assert.False(t, pv.validatePacketIntegrity(invalidEAPPacket, 1))
}

func TestPacketValidator_ValidatePacket_FullIntegration(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	// Create a complete valid Access-Request packet
	requestAuth, err := GenerateRequestAuthenticator()
	require.NoError(t, err)

	packetData := []byte{
		0x01, 0x42, // Code: Access-Request, Identifier: 66
		0x00, 0x20, // Length: 32 bytes
	}
	packetData = append(packetData, requestAuth[:]...) // Request Authenticator
	packetData = append(packetData, []byte{
		// User-Name attribute
		0x01, 0x06, 0x74, 0x65, 0x73, 0x74,
		// User-Password attribute
		0x02, 0x06, 0x70, 0x61, 0x73, 0x73,
	}...)

	result, err := pv.ValidatePacket(packetData, 1, 0x42, nil)
	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.True(t, result.AuthenticatorValid)
	assert.True(t, result.MessageAuthValid)
	assert.True(t, result.IntegrityValid)
	assert.Empty(t, result.Errors)
}

func TestPacketValidator_ConcurrentValidation(t *testing.T) {
	sharedSecret := []byte("secret123")
	pv := NewPacketValidator(sharedSecret)

	// Create a valid packet
	packetData := []byte{
		0x01, 0x00, // Code, Identifier
		0x00, 0x14, // Length: 20 bytes
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Authenticator
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	done := make(chan bool, 10)

	// Run concurrent validations
	for i := 0; i < 10; i++ {
		go func() {
			result, err := pv.ValidatePacket(packetData, 1, 0, nil)
			assert.NoError(t, err)
			assert.NotNil(t, result)
			done <- true
		}()
	}

	// Wait for all to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}
