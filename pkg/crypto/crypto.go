package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"errors"
	"fmt"
)

// AuthenticatorLength is the length of RADIUS authenticators in bytes
const AuthenticatorLength = 16

// Authenticator represents a 16-byte RADIUS authenticator
type Authenticator [AuthenticatorLength]byte

// GenerateRequestAuthenticator generates a random Request Authenticator
func GenerateRequestAuthenticator() (Authenticator, error) {
	var auth Authenticator
	_, err := rand.Read(auth[:])
	if err != nil {
		return auth, fmt.Errorf("failed to generate random authenticator: %w", err)
	}
	return auth, nil
}

// CalculateResponseAuthenticator calculates the Response Authenticator as defined in RFC 2865
// Response Authenticator = MD5(Code + ID + Length + Request Authenticator + Response Attributes + Secret)
func CalculateResponseAuthenticator(code uint8, identifier uint8, length uint16, requestAuth Authenticator, responseData []byte, sharedSecret []byte) Authenticator {
	hash := md5.New()

	// Code (1 byte)
	hash.Write([]byte{code})

	// Identifier (1 byte)
	hash.Write([]byte{identifier})

	// Length (2 bytes, big-endian)
	hash.Write([]byte{byte(length >> 8), byte(length)})

	// Request Authenticator (16 bytes)
	hash.Write(requestAuth[:])

	// Response Attributes (variable length)
	hash.Write(responseData)

	// Shared Secret
	hash.Write(sharedSecret)

	var result Authenticator
	copy(result[:], hash.Sum(nil))
	return result
}

// ValidateResponseAuthenticator validates a Response Authenticator
func ValidateResponseAuthenticator(code uint8, identifier uint8, length uint16, requestAuth Authenticator, responseData []byte, receivedAuth Authenticator, sharedSecret []byte) bool {
	expected := CalculateResponseAuthenticator(code, identifier, length, requestAuth, responseData, sharedSecret)
	return hmac.Equal(expected[:], receivedAuth[:])
}

// CalculateRequestAuthenticator calculates the Request Authenticator for Accounting packets
// Request Authenticator = MD5(Code + ID + Length + 16 zero octets + Request Attributes + Secret)
func CalculateRequestAuthenticator(code uint8, identifier uint8, length uint16, requestData []byte, sharedSecret []byte) Authenticator {
	hash := md5.New()

	// Code (1 byte)
	hash.Write([]byte{code})

	// Identifier (1 byte)
	hash.Write([]byte{identifier})

	// Length (2 bytes, big-endian)
	hash.Write([]byte{byte(length >> 8), byte(length)})

	// 16 zero octets (placeholder for authenticator)
	hash.Write(make([]byte, AuthenticatorLength))

	// Request Attributes (variable length)
	hash.Write(requestData)

	// Shared Secret
	hash.Write(sharedSecret)

	var result Authenticator
	copy(result[:], hash.Sum(nil))
	return result
}

// ValidateRequestAuthenticator validates a Request Authenticator for Accounting packets
func ValidateRequestAuthenticator(code uint8, identifier uint8, length uint16, requestData []byte, receivedAuth Authenticator, sharedSecret []byte) bool {
	expected := CalculateRequestAuthenticator(code, identifier, length, requestData, sharedSecret)
	return hmac.Equal(expected[:], receivedAuth[:])
}

// ZeroAuthenticator returns an authenticator filled with zeros
func ZeroAuthenticator() Authenticator {
	return Authenticator{}
}

// String returns a hex representation of the authenticator
func (a Authenticator) String() string {
	return fmt.Sprintf("%x", a[:])
}

// Equal compares two authenticators for equality
func (a Authenticator) Equal(other Authenticator) bool {
	return hmac.Equal(a[:], other[:])
}

// IsZero returns true if the authenticator is all zeros
func (a Authenticator) IsZero() bool {
	zero := ZeroAuthenticator()
	return a.Equal(zero)
}

// FromBytes creates an authenticator from a byte slice
func FromBytes(data []byte) (Authenticator, error) {
	var auth Authenticator
	if len(data) != AuthenticatorLength {
		return auth, fmt.Errorf("authenticator must be exactly %d bytes, got %d", AuthenticatorLength, len(data))
	}
	copy(auth[:], data)
	return auth, nil
}

// ToBytes returns the authenticator as a byte slice
func (a Authenticator) ToBytes() []byte {
	result := make([]byte, AuthenticatorLength)
	copy(result, a[:])
	return result
}

var (
	// ErrInvalidAuthenticatorLength indicates an invalid authenticator length
	ErrInvalidAuthenticatorLength = errors.New("invalid authenticator length")
	// ErrAuthenticatorMismatch indicates authenticator validation failed
	ErrAuthenticatorMismatch = errors.New("authenticator validation failed")
)
