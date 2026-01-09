package goradius

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
)

const (
	// CHAPChallengeLength is the default length of a CHAP challenge in bytes.
	CHAPChallengeLength = 16

	// CHAPResponseLength is the length of the CHAP response (MD5 hash).
	CHAPResponseLength = 16
)

// GenerateCHAPChallenge generates a random CHAP challenge.
// The challenge is typically 16 bytes but can be any length from 1 to 255 bytes.
func GenerateCHAPChallenge(length int) ([]byte, error) {
	if length <= 0 {
		length = CHAPChallengeLength
	}

	if length > 255 {
		length = 255
	}

	challenge := make([]byte, length)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}

	return challenge, nil
}

// GenerateCHAPResponse generates a CHAP response from the given identifier, password, and challenge.
// The response is calculated as: MD5(identifier + password + challenge)
// Returns a 17-byte slice: 1 byte identifier + 16 bytes MD5 hash (CHAP-Password format per RFC 2865).
func GenerateCHAPResponse(identifier byte, password, challenge []byte) []byte {
	hash := md5.New()
	hash.Write([]byte{identifier})
	hash.Write(password)
	hash.Write(challenge)

	response := make([]byte, 1+CHAPResponseLength)
	response[0] = identifier
	copy(response[1:], hash.Sum(nil))

	return response
}

// CheckCHAPPassword verifies if the provided password matches the CHAP response.
// The chapPassword should be in CHAP-Password format: 1 byte identifier + 16 bytes hash.
// Returns true if the password is correct, false otherwise.
func CheckCHAPPassword(chapPassword, password, challenge []byte) bool {
	if len(chapPassword) != 1+CHAPResponseLength {
		return false
	}

	identifier := chapPassword[0]
	expected := GenerateCHAPResponse(identifier, password, challenge)

	return subtle.ConstantTimeCompare(chapPassword, expected) == 1
}
