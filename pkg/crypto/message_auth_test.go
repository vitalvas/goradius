package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCalculateMessageAuthenticator(t *testing.T) {
	// Create a sample RADIUS packet
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	sharedSecret := []byte("secret")

	msgAuth, err := CalculateMessageAuthenticator(packetData, sharedSecret)
	require.NoError(t, err)
	assert.Len(t, msgAuth, MessageAuthenticatorLength)

	// Should be deterministic
	msgAuth2, err := CalculateMessageAuthenticator(packetData, sharedSecret)
	require.NoError(t, err)
	assert.Equal(t, msgAuth, msgAuth2)

	// Different shared secret should produce different result
	msgAuth3, err := CalculateMessageAuthenticator(packetData, []byte("different"))
	require.NoError(t, err)
	assert.NotEqual(t, msgAuth, msgAuth3)
}

func TestCalculateMessageAuthenticatorErrors(t *testing.T) {
	// Test with packet too short
	shortPacket := []byte{0x01, 0x42, 0x00, 0x04}
	sharedSecret := []byte("secret")

	_, err := CalculateMessageAuthenticator(shortPacket, sharedSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "packet too short")
}

func TestValidateMessageAuthenticator(t *testing.T) {
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	sharedSecret := []byte("secret")

	// Calculate Message-Authenticator
	msgAuth, err := CalculateMessageAuthenticator(packetData, sharedSecret)
	require.NoError(t, err)

	// Valid authenticator should pass
	valid, err := ValidateMessageAuthenticator(packetData, sharedSecret, msgAuth)
	require.NoError(t, err)
	assert.True(t, valid)

	// Invalid authenticator should fail
	invalidAuth := msgAuth
	invalidAuth[0] ^= 0xFF
	valid, err = ValidateMessageAuthenticator(packetData, sharedSecret, invalidAuth)
	require.NoError(t, err)
	assert.False(t, valid)

	// Wrong shared secret should fail
	valid, err = ValidateMessageAuthenticator(packetData, []byte("wrong"), msgAuth)
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestAddMessageAuthenticator(t *testing.T) {
	// Create a packet without Message-Authenticator
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	sharedSecret := []byte("secret")

	newPacketData, err := AddMessageAuthenticator(packetData, sharedSecret)
	require.NoError(t, err)

	// Packet should be longer (added 18 bytes: type + length + value)
	assert.Equal(t, len(packetData)+18, len(newPacketData))

	// Length field should be updated
	newLength := uint16(newPacketData[2])<<8 | uint16(newPacketData[3])
	assert.Equal(t, uint16(len(newPacketData)), newLength)

	// Should contain Message-Authenticator attribute
	assert.True(t, HasMessageAuthenticator(newPacketData))

	// Extract and validate the Message-Authenticator
	msgAuth, err := ExtractMessageAuthenticator(newPacketData)
	require.NoError(t, err)

	valid, err := ValidateMessageAuthenticator(newPacketData, sharedSecret, msgAuth)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestAddMessageAuthenticatorAlreadyExists(t *testing.T) {
	// Create a packet with Message-Authenticator already present
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x26, // Length: 38
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		// Message-Authenticator (type=80, length=18, value=16 zeros)
		0x50, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	sharedSecret := []byte("secret")

	_, err := AddMessageAuthenticator(packetData, sharedSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestUpdateMessageAuthenticator(t *testing.T) {
	// Create a packet with Message-Authenticator
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x26, // Length: 38
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		// Message-Authenticator (type=80, length=18, value=16 zeros)
		0x50, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	sharedSecret := []byte("secret")

	// Update Message-Authenticator
	err := UpdateMessageAuthenticator(packetData, sharedSecret)
	require.NoError(t, err)

	// Extract and validate the updated Message-Authenticator
	msgAuth, err := ExtractMessageAuthenticator(packetData)
	require.NoError(t, err)

	valid, err := ValidateMessageAuthenticator(packetData, sharedSecret, msgAuth)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestUpdateMessageAuthenticatorNotFound(t *testing.T) {
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	sharedSecret := []byte("secret")

	err := UpdateMessageAuthenticator(packetData, sharedSecret)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestRemoveMessageAuthenticator(t *testing.T) {
	// Create a packet with Message-Authenticator
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x26, // Length: 38
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		// Message-Authenticator (type=80, length=18, value=16 zeros)
		0x50, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	newPacketData, err := RemoveMessageAuthenticator(packetData)
	require.NoError(t, err)

	// Packet should be shorter (removed 18 bytes)
	assert.Equal(t, len(packetData)-18, len(newPacketData))

	// Length field should be updated
	newLength := uint16(newPacketData[2])<<8 | uint16(newPacketData[3])
	assert.Equal(t, uint16(len(newPacketData)), newLength)

	// Should not contain Message-Authenticator attribute
	assert.False(t, HasMessageAuthenticator(newPacketData))
}

func TestRemoveMessageAuthenticatorNotFound(t *testing.T) {
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	// Should return the original packet unchanged
	newPacketData, err := RemoveMessageAuthenticator(packetData)
	require.NoError(t, err)
	assert.Equal(t, packetData, newPacketData)
}

func TestHasMessageAuthenticator(t *testing.T) {
	// Packet without Message-Authenticator
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	assert.False(t, HasMessageAuthenticator(packetData))

	// Add Message-Authenticator
	sharedSecret := []byte("secret")
	packetWithAuth, err := AddMessageAuthenticator(packetData, sharedSecret)
	require.NoError(t, err)

	assert.True(t, HasMessageAuthenticator(packetWithAuth))
}

func TestExtractMessageAuthenticator(t *testing.T) {
	// Create a packet with Message-Authenticator
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x26, // Length: 38
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		// Message-Authenticator (type=80, length=18, value=test pattern)
		0x50, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
		0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
		0x0f, 0x10,
	}

	msgAuth, err := ExtractMessageAuthenticator(packetData)
	require.NoError(t, err)

	expected := [MessageAuthenticatorLength]byte{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	assert.Equal(t, expected, msgAuth)
}

func TestExtractMessageAuthenticatorNotFound(t *testing.T) {
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	_, err := ExtractMessageAuthenticator(packetData)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestMessageAuthenticatorHandler(t *testing.T) {
	sharedSecret := []byte("secret")
	handler := NewMessageAuthenticatorHandler(sharedSecret)

	assert.Equal(t, sharedSecret, handler.SharedSecret)

	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	// Test Calculate
	msgAuth, err := handler.Calculate(packetData)
	require.NoError(t, err)
	assert.Len(t, msgAuth, MessageAuthenticatorLength)

	// Test Validate
	valid, err := handler.Validate(packetData, msgAuth)
	require.NoError(t, err)
	assert.True(t, valid)

	// Test Add
	packetWithAuth, err := handler.Add(packetData)
	require.NoError(t, err)
	assert.True(t, HasMessageAuthenticator(packetWithAuth))

	// Test ValidatePacket
	valid, err = handler.ValidatePacket(packetWithAuth)
	require.NoError(t, err)
	assert.True(t, valid)

	// Test SignPacket (add new)
	signedPacket, err := handler.SignPacket(packetData)
	require.NoError(t, err)
	assert.True(t, HasMessageAuthenticator(signedPacket))

	// Test SignPacket (update existing)
	signedPacket2, err := handler.SignPacket(signedPacket)
	require.NoError(t, err)
	assert.Equal(t, signedPacket, signedPacket2) // Should be the same packet with updated auth
}

func TestMessageAuthenticatorWithZeroValue(t *testing.T) {
	// Test calculation with Message-Authenticator containing zeros
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x26, // Length: 38
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		// Message-Authenticator (type=80, length=18, value=16 zeros)
		0x50, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00,
	}

	sharedSecret := []byte("secret")

	// Should properly zero out the Message-Authenticator value for calculation
	msgAuth, err := CalculateMessageAuthenticator(packetData, sharedSecret)
	require.NoError(t, err)
	assert.Len(t, msgAuth, MessageAuthenticatorLength)

	// The calculated value should not be all zeros
	allZeros := [MessageAuthenticatorLength]byte{}
	assert.NotEqual(t, allZeros, msgAuth)
}

func TestMessageAuthenticatorConcurrency(t *testing.T) {
	packetData := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x20, // Length: 32
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attributes (12 bytes)
		0x01, 0x06, 0x00, 0x00, 0x00, 0x01, // Service-Type = Login
		0x04, 0x06, 0x01, 0x02, 0x03, 0x04, // NAS-IP-Address
	}

	sharedSecret := []byte("secret")
	done := make(chan [MessageAuthenticatorLength]byte, 10)

	// Test concurrent Message-Authenticator calculation
	for i := 0; i < 10; i++ {
		go func() {
			msgAuth, err := CalculateMessageAuthenticator(packetData, sharedSecret)
			assert.NoError(t, err)
			done <- msgAuth
		}()
	}

	// Collect all results
	results := make([][MessageAuthenticatorLength]byte, 10)
	for i := 0; i < 10; i++ {
		results[i] = <-done
	}

	// All results should be identical (deterministic)
	for i := 1; i < 10; i++ {
		assert.Equal(t, results[0], results[i])
	}
}

func TestMessageAuthenticatorEdgeCases(t *testing.T) {
	sharedSecret := []byte("secret")

	// Test with minimum valid packet
	minPacket := []byte{
		0x01,       // Code: Access-Request
		0x42,       // Identifier: 66
		0x00, 0x14, // Length: 20 (minimum)
		// Request Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	}

	msgAuth, err := CalculateMessageAuthenticator(minPacket, sharedSecret)
	require.NoError(t, err)
	assert.Len(t, msgAuth, MessageAuthenticatorLength)

	// Test with maximum practical packet (within reason)
	maxAttrs := make([]byte, 4000) // Large attribute section
	for i := range maxAttrs {
		maxAttrs[i] = byte(i % 256)
	}

	minPacket = append(minPacket, maxAttrs...)
	maxPacket := minPacket
	// Update length
	newLength := len(maxPacket)
	maxPacket[2] = byte(newLength >> 8)
	maxPacket[3] = byte(newLength)

	msgAuth, err = CalculateMessageAuthenticator(maxPacket, sharedSecret)
	require.NoError(t, err)
	assert.Len(t, msgAuth, MessageAuthenticatorLength)
}
