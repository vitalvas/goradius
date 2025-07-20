package crypto

import (
	"crypto/hmac"
	"crypto/md5"
	"fmt"
)

// Message-Authenticator implementation as defined in RFC 2869

const (
	// MessageAuthenticatorLength is the length of the Message-Authenticator attribute
	MessageAuthenticatorLength = 16
)

// CalculateMessageAuthenticator calculates the Message-Authenticator for a RADIUS packet
// Message-Authenticator = HMAC-MD5(shared_secret, packet_with_zero_authenticator)
func CalculateMessageAuthenticator(packetData []byte, sharedSecret []byte) ([MessageAuthenticatorLength]byte, error) {
	var result [MessageAuthenticatorLength]byte

	if len(packetData) < 20 {
		return result, fmt.Errorf("packet too short for Message-Authenticator calculation")
	}

	// Create a copy of the packet data for calculation
	calcData := make([]byte, len(packetData))
	copy(calcData, packetData)

	// Zero out the Message-Authenticator field if it exists
	msgAuthOffset := findMessageAuthenticatorOffset(calcData)
	if msgAuthOffset != -1 {
		// Zero out the 16-byte value field of the Message-Authenticator attribute
		for i := 0; i < MessageAuthenticatorLength; i++ {
			calcData[msgAuthOffset+i] = 0
		}
	}

	// Calculate HMAC-MD5
	mac := hmac.New(md5.New, sharedSecret)
	mac.Write(calcData)

	copy(result[:], mac.Sum(nil))
	return result, nil
}

// ValidateMessageAuthenticator validates the Message-Authenticator in a RADIUS packet
func ValidateMessageAuthenticator(packetData []byte, sharedSecret []byte, receivedAuth [MessageAuthenticatorLength]byte) (bool, error) {
	expected, err := CalculateMessageAuthenticator(packetData, sharedSecret)
	if err != nil {
		return false, err
	}

	return hmac.Equal(expected[:], receivedAuth[:]), nil
}

// AddMessageAuthenticator adds a Message-Authenticator attribute to packet data
func AddMessageAuthenticator(packetData []byte, sharedSecret []byte) ([]byte, error) {
	// Check if Message-Authenticator already exists
	if findMessageAuthenticatorOffset(packetData) != -1 {
		return nil, fmt.Errorf("Message-Authenticator already exists in packet")
	}

	// Add Message-Authenticator attribute with zero value initially
	msgAuthAttr := make([]byte, 18) // Type(1) + Length(1) + Value(16)
	msgAuthAttr[0] = 80             // Message-Authenticator attribute type
	msgAuthAttr[1] = 18             // Attribute length
	// Value is already zeros

	// Append to packet
	packetData = append(packetData, msgAuthAttr...)

	// Update packet length
	newLength := len(packetData)
	packetData[2] = byte(newLength >> 8)
	packetData[3] = byte(newLength)

	// Calculate and set the actual Message-Authenticator value
	msgAuth, err := CalculateMessageAuthenticator(packetData, sharedSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate Message-Authenticator: %w", err)
	}

	// Set the calculated value in the attribute
	msgAuthOffset := len(packetData) - 16 // Offset to the value field
	copy(packetData[msgAuthOffset:], msgAuth[:])

	return packetData, nil
}

// UpdateMessageAuthenticator updates the Message-Authenticator in existing packet data
func UpdateMessageAuthenticator(packetData []byte, sharedSecret []byte) error {
	msgAuthOffset := findMessageAuthenticatorOffset(packetData)
	if msgAuthOffset == -1 {
		return fmt.Errorf("Message-Authenticator not found in packet")
	}

	// Calculate new Message-Authenticator
	msgAuth, err := CalculateMessageAuthenticator(packetData, sharedSecret)
	if err != nil {
		return fmt.Errorf("failed to calculate Message-Authenticator: %w", err)
	}

	// Update the value in the packet
	copy(packetData[msgAuthOffset:], msgAuth[:])

	return nil
}

// RemoveMessageAuthenticator removes the Message-Authenticator attribute from packet data
func RemoveMessageAuthenticator(packetData []byte) ([]byte, error) {
	msgAuthStart := findMessageAuthenticatorStart(packetData)
	if msgAuthStart == -1 {
		return packetData, nil // No Message-Authenticator to remove
	}

	// Remove the entire attribute (type + length + value = 18 bytes)
	newPacketData := make([]byte, 0, len(packetData)-18)
	newPacketData = append(newPacketData, packetData[:msgAuthStart]...)
	newPacketData = append(newPacketData, packetData[msgAuthStart+18:]...)

	// Update packet length
	newLength := len(newPacketData)
	newPacketData[2] = byte(newLength >> 8)
	newPacketData[3] = byte(newLength)

	return newPacketData, nil
}

// findMessageAuthenticatorOffset finds the offset of the Message-Authenticator value field
func findMessageAuthenticatorOffset(packetData []byte) int {
	start := findMessageAuthenticatorStart(packetData)
	if start == -1 {
		return -1
	}
	return start + 2 // Skip type and length fields
}

// findMessageAuthenticatorStart finds the start of the Message-Authenticator attribute
func findMessageAuthenticatorStart(packetData []byte) int {
	if len(packetData) < 20 {
		return -1
	}

	// Parse attributes starting after the header
	offset := 20
	for offset < len(packetData) {
		if offset+2 > len(packetData) {
			break
		}

		attrType := packetData[offset]
		attrLength := packetData[offset+1]

		if attrLength < 2 || offset+int(attrLength) > len(packetData) {
			break
		}

		if attrType == 80 { // Message-Authenticator type
			return offset
		}

		offset += int(attrLength)
	}

	return -1
}

// HasMessageAuthenticator checks if the packet contains a Message-Authenticator attribute
func HasMessageAuthenticator(packetData []byte) bool {
	return findMessageAuthenticatorStart(packetData) != -1
}

// ExtractMessageAuthenticator extracts the Message-Authenticator value from packet data
func ExtractMessageAuthenticator(packetData []byte) ([MessageAuthenticatorLength]byte, error) {
	var result [MessageAuthenticatorLength]byte

	msgAuthOffset := findMessageAuthenticatorOffset(packetData)
	if msgAuthOffset == -1 {
		return result, fmt.Errorf("Message-Authenticator not found in packet")
	}

	if msgAuthOffset+MessageAuthenticatorLength > len(packetData) {
		return result, fmt.Errorf("Message-Authenticator value extends beyond packet")
	}

	copy(result[:], packetData[msgAuthOffset:msgAuthOffset+MessageAuthenticatorLength])
	return result, nil
}

// MessageAuthenticatorHandler provides utilities for handling Message-Authenticator
type MessageAuthenticatorHandler struct {
	SharedSecret []byte
}

// NewMessageAuthenticatorHandler creates a new Message-Authenticator handler
func NewMessageAuthenticatorHandler(sharedSecret []byte) *MessageAuthenticatorHandler {
	return &MessageAuthenticatorHandler{
		SharedSecret: sharedSecret,
	}
}

// Calculate calculates the Message-Authenticator for a packet
func (mah *MessageAuthenticatorHandler) Calculate(packetData []byte) ([MessageAuthenticatorLength]byte, error) {
	return CalculateMessageAuthenticator(packetData, mah.SharedSecret)
}

// Validate validates the Message-Authenticator in a packet
func (mah *MessageAuthenticatorHandler) Validate(packetData []byte, receivedAuth [MessageAuthenticatorLength]byte) (bool, error) {
	return ValidateMessageAuthenticator(packetData, mah.SharedSecret, receivedAuth)
}

// Add adds a Message-Authenticator to a packet
func (mah *MessageAuthenticatorHandler) Add(packetData []byte) ([]byte, error) {
	return AddMessageAuthenticator(packetData, mah.SharedSecret)
}

// Update updates the Message-Authenticator in a packet
func (mah *MessageAuthenticatorHandler) Update(packetData []byte) error {
	return UpdateMessageAuthenticator(packetData, mah.SharedSecret)
}

// ValidatePacket validates a complete packet with Message-Authenticator
func (mah *MessageAuthenticatorHandler) ValidatePacket(packetData []byte) (bool, error) {
	if !HasMessageAuthenticator(packetData) {
		return false, fmt.Errorf("packet does not contain Message-Authenticator")
	}

	receivedAuth, err := ExtractMessageAuthenticator(packetData)
	if err != nil {
		return false, fmt.Errorf("failed to extract Message-Authenticator: %w", err)
	}

	return mah.Validate(packetData, receivedAuth)
}

// SignPacket signs a packet by adding or updating the Message-Authenticator
func (mah *MessageAuthenticatorHandler) SignPacket(packetData []byte) ([]byte, error) {
	if HasMessageAuthenticator(packetData) {
		// Update existing Message-Authenticator
		err := mah.Update(packetData)
		return packetData, err
	}

	// Add new Message-Authenticator
	return mah.Add(packetData)
}
