package crypto

import (
	"fmt"
)

// PacketValidationError represents validation errors
type PacketValidationError struct {
	Type    string
	Message string
}

func (e *PacketValidationError) Error() string {
	return fmt.Sprintf("%s validation error: %s", e.Type, e.Message)
}

// ValidationResult contains the results of packet validation
type ValidationResult struct {
	Valid              bool
	Errors             []PacketValidationError
	AuthenticatorValid bool
	MessageAuthValid   bool
	IntegrityValid     bool
}

// PacketValidator provides comprehensive packet validation functionality
type PacketValidator struct {
	SharedSecret []byte
}

// NewPacketValidator creates a new packet validator
func NewPacketValidator(sharedSecret []byte) *PacketValidator {
	return &PacketValidator{
		SharedSecret: sharedSecret,
	}
}

// ValidatePacket performs comprehensive validation of a RADIUS packet
func (pv *PacketValidator) ValidatePacket(packetData []byte, packetType uint8, identifier uint8, requestAuth *Authenticator) (*ValidationResult, error) {
	result := &ValidationResult{
		Valid:  true,
		Errors: make([]PacketValidationError, 0),
	}

	// Basic packet structure validation
	if err := pv.validatePacketStructure(packetData); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, PacketValidationError{
			Type:    "Structure",
			Message: err.Error(),
		})
		return result, nil
	}

	// Validate packet length consistency
	if err := pv.validatePacketLength(packetData); err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, PacketValidationError{
			Type:    "Length",
			Message: err.Error(),
		})
		return result, nil
	}

	// Validate authenticator based on packet type
	authValid, err := pv.validateAuthenticator(packetData, packetType, identifier, requestAuth)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, PacketValidationError{
			Type:    "Authenticator",
			Message: err.Error(),
		})
	}
	result.AuthenticatorValid = authValid

	// Validate Message-Authenticator if present
	msgAuthValid, err := pv.validateMessageAuthenticator(packetData)
	if err != nil {
		result.Valid = false
		result.Errors = append(result.Errors, PacketValidationError{
			Type:    "MessageAuthenticator",
			Message: err.Error(),
		})
	}
	result.MessageAuthValid = msgAuthValid

	// Validate overall packet integrity
	integrityValid := pv.validatePacketIntegrity(packetData, packetType)
	result.IntegrityValid = integrityValid

	if !authValid || !msgAuthValid || !integrityValid {
		result.Valid = false
	}

	return result, nil
}

// validatePacketStructure performs basic structural validation
func (pv *PacketValidator) validatePacketStructure(packetData []byte) error {
	if len(packetData) < 20 {
		return fmt.Errorf("packet too short: minimum 20 bytes required, got %d", len(packetData))
	}

	if len(packetData) > 4096 {
		return fmt.Errorf("packet too large: maximum 4096 bytes allowed, got %d", len(packetData))
	}

	return nil
}

// validatePacketLength validates that the packet length field matches actual length
func (pv *PacketValidator) validatePacketLength(packetData []byte) error {
	if len(packetData) < 4 {
		return fmt.Errorf("packet too short to contain length field")
	}

	declaredLength := (uint16(packetData[2]) << 8) | uint16(packetData[3])
	actualLength := uint16(len(packetData))

	if declaredLength != actualLength {
		return fmt.Errorf("length mismatch: declared %d, actual %d", declaredLength, actualLength)
	}

	return nil
}

// validateAuthenticator validates the appropriate authenticator based on packet type
func (pv *PacketValidator) validateAuthenticator(packetData []byte, packetType uint8, identifier uint8, requestAuth *Authenticator) (bool, error) {
	if len(packetData) < 20 {
		return false, fmt.Errorf("packet too short for authenticator validation")
	}

	// Extract the authenticator from the packet
	var receivedAuth Authenticator
	copy(receivedAuth[:], packetData[4:20])

	switch packetType {
	case 1: // Access-Request
		// For Access-Request, the authenticator should be random (we can't validate it without knowing if it's original)
		// But we can check it's not all zeros
		if receivedAuth.IsZero() {
			return false, fmt.Errorf("Access-Request authenticator cannot be all zeros")
		}
		return true, nil

	case 2, 3, 5: // Access-Accept, Access-Reject, Accounting-Response
		if requestAuth == nil {
			return false, fmt.Errorf("request authenticator required for response validation")
		}

		// Calculate expected Response Authenticator
		length := (uint16(packetData[2]) << 8) | uint16(packetData[3])

		// Create packet data with zero authenticator for calculation
		calcData := make([]byte, len(packetData))
		copy(calcData, packetData)
		copy(calcData[4:20], make([]byte, 16)) // Zero out authenticator field

		expectedAuth := CalculateResponseAuthenticator(
			packetType, identifier, length, *requestAuth,
			calcData[20:], pv.SharedSecret,
		)

		return expectedAuth.Equal(receivedAuth), nil

	case 4, 12, 13: // Accounting-Request, Status-Server, Status-Client
		// Calculate expected Request Authenticator
		length := (uint16(packetData[2]) << 8) | uint16(packetData[3])

		// Create packet data with zero authenticator for calculation
		calcData := make([]byte, len(packetData))
		copy(calcData, packetData)
		copy(calcData[4:20], make([]byte, 16)) // Zero out authenticator field

		expectedAuth := CalculateRequestAuthenticator(
			packetType, identifier, length,
			calcData[20:], pv.SharedSecret,
		)

		return expectedAuth.Equal(receivedAuth), nil

	default:
		return false, fmt.Errorf("unknown packet type for authenticator validation: %d", packetType)
	}
}

// validateMessageAuthenticator validates Message-Authenticator if present
func (pv *PacketValidator) validateMessageAuthenticator(packetData []byte) (bool, error) {
	if !HasMessageAuthenticator(packetData) {
		// No Message-Authenticator present, which is valid for most packet types
		return true, nil
	}

	// Extract the Message-Authenticator
	receivedAuth, err := ExtractMessageAuthenticator(packetData)
	if err != nil {
		return false, fmt.Errorf("failed to extract Message-Authenticator: %w", err)
	}

	// Validate it
	valid, err := ValidateMessageAuthenticator(packetData, pv.SharedSecret, receivedAuth)
	if err != nil {
		return false, fmt.Errorf("failed to validate Message-Authenticator: %w", err)
	}

	return valid, nil
}

// validatePacketIntegrity performs additional integrity checks
func (pv *PacketValidator) validatePacketIntegrity(packetData []byte, _ uint8) bool {
	// Validate attributes structure
	if !pv.validateAttributesStructure(packetData) {
		return false
	}

	// Check for required Message-Authenticator in EAP packets
	if pv.isEAPPacket(packetData) && !HasMessageAuthenticator(packetData) {
		return false
	}

	return true
}

// validateAttributesStructure validates the structure of all attributes in the packet
func (pv *PacketValidator) validateAttributesStructure(packetData []byte) bool {
	if len(packetData) < 20 {
		return false
	}

	offset := 20 // Start after header
	for offset < len(packetData) {
		if offset+2 > len(packetData) {
			return false // Not enough space for type and length
		}

		attrLength := packetData[offset+1]
		if attrLength < 2 {
			return false // Invalid attribute length
		}

		if offset+int(attrLength) > len(packetData) {
			return false // Attribute extends beyond packet
		}

		offset += int(attrLength)
	}

	return offset == len(packetData) // Should end exactly at packet boundary
}

// isEAPPacket checks if the packet contains EAP-Message attributes
func (pv *PacketValidator) isEAPPacket(packetData []byte) bool {
	if len(packetData) < 20 {
		return false
	}

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

		if attrType == 79 { // EAP-Message attribute type
			return true
		}

		offset += int(attrLength)
	}

	return false
}

// hasAttribute checks if a packet contains an attribute of the specified type
func (pv *PacketValidator) hasAttribute(packetData []byte, attrType uint8) bool {
	if len(packetData) < 20 {
		return false
	}

	offset := 20
	for offset < len(packetData) {
		if offset+2 > len(packetData) {
			break
		}

		currentAttrType := packetData[offset]
		attrLength := packetData[offset+1]

		if attrLength < 2 || offset+int(attrLength) > len(packetData) {
			break
		}

		if currentAttrType == attrType {
			return true
		}

		offset += int(attrLength)
	}

	return false
}

// SecurityValidator provides high-level security validation functionality
type SecurityValidator struct {
	packetValidator *PacketValidator
}

// NewSecurityValidator creates a new security validator
func NewSecurityValidator(sharedSecret []byte) *SecurityValidator {
	return &SecurityValidator{
		packetValidator: NewPacketValidator(sharedSecret),
	}
}

// ValidateAuthentication performs comprehensive authentication validation
func (sv *SecurityValidator) ValidateAuthentication(packetData []byte, packetType uint8, identifier uint8, requestAuth *Authenticator, protocol string) (*ValidationResult, error) {
	// Validate the packet structure and authenticators
	result, err := sv.packetValidator.ValidatePacket(packetData, packetType, identifier, requestAuth)
	if err != nil {
		return nil, err
	}

	// Authentication protocols are not supported
	result.Valid = false
	result.Errors = append(result.Errors, PacketValidationError{
		Type:    "Protocol",
		Message: fmt.Sprintf("authentication protocol %s is not supported - all authentication methods have been removed", protocol),
	})

	return result, nil
}

// ValidateIntegrity performs integrity validation only
func (sv *SecurityValidator) ValidateIntegrity(packetData []byte) bool {
	return sv.packetValidator.validatePacketIntegrity(packetData, 0)
}

// ValidateStructure performs structural validation only
func (sv *SecurityValidator) ValidateStructure(packetData []byte) error {
	if err := sv.packetValidator.validatePacketStructure(packetData); err != nil {
		return err
	}
	return sv.packetValidator.validatePacketLength(packetData)
}
