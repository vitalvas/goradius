package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateRequestAuthenticator(t *testing.T) {
	auth1, err := GenerateRequestAuthenticator()
	require.NoError(t, err)
	assert.Len(t, auth1, AuthenticatorLength)

	auth2, err := GenerateRequestAuthenticator()
	require.NoError(t, err)
	assert.Len(t, auth2, AuthenticatorLength)

	// Should be different (extremely unlikely to be the same)
	assert.NotEqual(t, auth1, auth2)
}

func TestCalculateResponseAuthenticator(t *testing.T) {
	// Test data from RFC 2865 examples
	requestAuth := Authenticator{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	sharedSecret := []byte("secret")
	responseData := []byte{0x01, 0x06, 0x00, 0x00, 0x00, 0x01} // Service-Type = Login

	responseAuth := CalculateResponseAuthenticator(2, 123, 26, requestAuth, responseData, sharedSecret)

	assert.Len(t, responseAuth, AuthenticatorLength)
	assert.NotEqual(t, ZeroAuthenticator(), responseAuth)

	// Should be deterministic
	responseAuth2 := CalculateResponseAuthenticator(2, 123, 26, requestAuth, responseData, sharedSecret)
	assert.Equal(t, responseAuth, responseAuth2)
}

func TestValidateResponseAuthenticator(t *testing.T) {
	requestAuth := Authenticator{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	sharedSecret := []byte("secret")
	responseData := []byte{0x01, 0x06, 0x00, 0x00, 0x00, 0x01}

	responseAuth := CalculateResponseAuthenticator(2, 123, 26, requestAuth, responseData, sharedSecret)

	// Valid authenticator should pass
	valid := ValidateResponseAuthenticator(2, 123, 26, requestAuth, responseData, responseAuth, sharedSecret)
	assert.True(t, valid)

	// Invalid authenticator should fail
	invalidAuth := responseAuth
	invalidAuth[0] ^= 0xFF
	valid = ValidateResponseAuthenticator(2, 123, 26, requestAuth, responseData, invalidAuth, sharedSecret)
	assert.False(t, valid)

	// Wrong shared secret should fail
	wrongSecret := []byte("wrongsecret")
	valid = ValidateResponseAuthenticator(2, 123, 26, requestAuth, responseData, responseAuth, wrongSecret)
	assert.False(t, valid)
}

func TestCalculateRequestAuthenticator(t *testing.T) {
	sharedSecret := []byte("secret")
	requestData := []byte{0x01, 0x06, 0x00, 0x00, 0x00, 0x01}

	requestAuth := CalculateRequestAuthenticator(4, 123, 26, requestData, sharedSecret)

	assert.Len(t, requestAuth, AuthenticatorLength)
	assert.NotEqual(t, ZeroAuthenticator(), requestAuth)

	// Should be deterministic
	requestAuth2 := CalculateRequestAuthenticator(4, 123, 26, requestData, sharedSecret)
	assert.Equal(t, requestAuth, requestAuth2)
}

func TestValidateRequestAuthenticator(t *testing.T) {
	sharedSecret := []byte("secret")
	requestData := []byte{0x01, 0x06, 0x00, 0x00, 0x00, 0x01}

	requestAuth := CalculateRequestAuthenticator(4, 123, 26, requestData, sharedSecret)

	// Valid authenticator should pass
	valid := ValidateRequestAuthenticator(4, 123, 26, requestData, requestAuth, sharedSecret)
	assert.True(t, valid)

	// Invalid authenticator should fail
	invalidAuth := requestAuth
	invalidAuth[0] ^= 0xFF
	valid = ValidateRequestAuthenticator(4, 123, 26, requestData, invalidAuth, sharedSecret)
	assert.False(t, valid)
}

func TestAuthenticatorHelpers(t *testing.T) {
	// Test ZeroAuthenticator
	zero := ZeroAuthenticator()
	for _, b := range zero {
		assert.Equal(t, uint8(0), b)
	}

	// Test GenerateRequestAuthenticator
	random, err := GenerateRequestAuthenticator()
	require.NoError(t, err)
	assert.Len(t, random, AuthenticatorLength)
	assert.NotEqual(t, zero, random)

	// Test String
	str := random.String()
	assert.Len(t, str, AuthenticatorLength*2) // Hex string is twice the length

	// Test Equal
	randomCopy := random
	assert.True(t, random.Equal(randomCopy))
	assert.False(t, random.Equal(zero))
	assert.True(t, zero.Equal(ZeroAuthenticator()))

	// Test IsZero
	assert.True(t, zero.IsZero())
	assert.False(t, random.IsZero())
}

func TestFromBytes(t *testing.T) {
	testData := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	auth, err := FromBytes(testData)
	require.NoError(t, err)

	for i, b := range testData {
		assert.Equal(t, b, auth[i])
	}

	// Test invalid length
	_, err = FromBytes([]byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must be exactly")
}

func TestToBytes(t *testing.T) {
	auth := Authenticator{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

	bytes := auth.ToBytes()
	assert.Len(t, bytes, AuthenticatorLength)

	for i, b := range auth {
		assert.Equal(t, b, bytes[i])
	}

	// Verify it's a copy (modifying bytes shouldn't affect original)
	bytes[0] = 0xFF
	assert.NotEqual(t, uint8(0xFF), auth[0])
}

func TestAuthenticatorConcurrency(t *testing.T) {
	// Test concurrent authenticator generation
	done := make(chan Authenticator, 10)

	for i := 0; i < 10; i++ {
		go func() {
			auth, err := GenerateRequestAuthenticator()
			assert.NoError(t, err)
			done <- auth
		}()
	}

	// Collect all authenticators
	authenticators := make([]Authenticator, 10)
	for i := 0; i < 10; i++ {
		authenticators[i] = <-done
	}

	// Verify they're all different
	for i := 0; i < 10; i++ {
		for j := i + 1; j < 10; j++ {
			assert.NotEqual(t, authenticators[i], authenticators[j])
		}
	}
}
