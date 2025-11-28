package tools

import (
	"crypto/md5"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCHAPChallenge(t *testing.T) {
	tests := []struct {
		name           string
		length         int
		expectedLength int
	}{
		{
			name:           "default length when zero",
			length:         0,
			expectedLength: CHAPChallengeLength,
		},
		{
			name:           "default length when negative",
			length:         -5,
			expectedLength: CHAPChallengeLength,
		},
		{
			name:           "custom length",
			length:         32,
			expectedLength: 32,
		},
		{
			name:           "maximum length capped at 255",
			length:         300,
			expectedLength: 255,
		},
		{
			name:           "minimum custom length",
			length:         1,
			expectedLength: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			challenge, err := GenerateCHAPChallenge(tt.length)
			require.NoError(t, err)
			assert.Len(t, challenge, tt.expectedLength)
		})
	}

	t.Run("generates unique challenges", func(t *testing.T) {
		challenge1, err := GenerateCHAPChallenge(CHAPChallengeLength)
		require.NoError(t, err)

		challenge2, err := GenerateCHAPChallenge(CHAPChallengeLength)
		require.NoError(t, err)

		assert.NotEqual(t, challenge1, challenge2)
	})
}

func TestGenerateCHAPResponse(t *testing.T) {
	tests := []struct {
		name       string
		identifier byte
		password   []byte
		challenge  []byte
	}{
		{
			name:       "basic response",
			identifier: 0x01,
			password:   []byte("password"),
			challenge:  []byte("0123456789abcdef"),
		},
		{
			name:       "empty password",
			identifier: 0x00,
			password:   []byte{},
			challenge:  []byte("challenge"),
		},
		{
			name:       "max identifier",
			identifier: 0xFF,
			password:   []byte("secret"),
			challenge:  []byte("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := GenerateCHAPResponse(tt.identifier, tt.password, tt.challenge)

			assert.Len(t, response, 1+CHAPResponseLength)
			assert.Equal(t, tt.identifier, response[0])

			hash := md5.New()
			hash.Write([]byte{tt.identifier})
			hash.Write(tt.password)
			hash.Write(tt.challenge)
			expectedHash := hash.Sum(nil)

			assert.Equal(t, expectedHash, response[1:])
		})
	}

	t.Run("different inputs produce different responses", func(t *testing.T) {
		challenge := []byte("0123456789abcdef")

		response1 := GenerateCHAPResponse(0x01, []byte("password1"), challenge)
		response2 := GenerateCHAPResponse(0x01, []byte("password2"), challenge)

		assert.NotEqual(t, response1, response2)
	})

	t.Run("different identifiers produce different responses", func(t *testing.T) {
		password := []byte("password")
		challenge := []byte("0123456789abcdef")

		response1 := GenerateCHAPResponse(0x01, password, challenge)
		response2 := GenerateCHAPResponse(0x02, password, challenge)

		assert.NotEqual(t, response1, response2)
	})
}

func TestCheckCHAPPassword(t *testing.T) {
	tests := []struct {
		name       string
		identifier byte
		password   []byte
		challenge  []byte
		checkPass  []byte
		expected   bool
	}{
		{
			name:       "correct password",
			identifier: 0x01,
			password:   []byte("password"),
			challenge:  []byte("0123456789abcdef"),
			checkPass:  []byte("password"),
			expected:   true,
		},
		{
			name:       "incorrect password",
			identifier: 0x01,
			password:   []byte("password"),
			challenge:  []byte("0123456789abcdef"),
			checkPass:  []byte("wrongpassword"),
			expected:   false,
		},
		{
			name:       "empty password matches empty",
			identifier: 0x00,
			password:   []byte{},
			challenge:  []byte("challenge"),
			checkPass:  []byte{},
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chapPassword := GenerateCHAPResponse(tt.identifier, tt.password, tt.challenge)
			result := CheckCHAPPassword(chapPassword, tt.checkPass, tt.challenge)
			assert.Equal(t, tt.expected, result)
		})
	}

	t.Run("invalid chap password length", func(t *testing.T) {
		result := CheckCHAPPassword([]byte("short"), []byte("password"), []byte("challenge"))
		assert.False(t, result)
	})

	t.Run("empty chap password", func(t *testing.T) {
		result := CheckCHAPPassword([]byte{}, []byte("password"), []byte("challenge"))
		assert.False(t, result)
	})

	t.Run("wrong challenge", func(t *testing.T) {
		identifier := byte(0x01)
		password := []byte("password")
		challenge1 := []byte("0123456789abcdef")
		challenge2 := []byte("fedcba9876543210")

		chapPassword := GenerateCHAPResponse(identifier, password, challenge1)
		result := CheckCHAPPassword(chapPassword, password, challenge2)

		assert.False(t, result)
	})
}

func BenchmarkGenerateCHAPChallenge(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GenerateCHAPChallenge(CHAPChallengeLength)
	}
}

func BenchmarkGenerateCHAPResponse(b *testing.B) {
	password := []byte("password")
	challenge := []byte("0123456789abcdef")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = GenerateCHAPResponse(byte(i), password, challenge)
	}
}

func BenchmarkCheckCHAPPassword(b *testing.B) {
	password := []byte("password")
	challenge := []byte("0123456789abcdef")
	chapPassword := GenerateCHAPResponse(0x01, password, challenge)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckCHAPPassword(chapPassword, password, challenge)
	}
}
