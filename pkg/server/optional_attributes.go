package server

import (
	"context"
	"fmt"

	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/packet"
)

// OptionalAttributeValidator provides validation for optional attributes
type OptionalAttributeValidator struct {
	dictionary *dictionary.Dictionary
	strict     bool
}

// OptionalAttributeOptions configures optional attribute validation behavior
type OptionalAttributeOptions struct {
	Dictionary *dictionary.Dictionary
	Strict     bool // If true, reject packets with unknown optional attributes
}

// NewOptionalAttributeValidator creates a new optional attribute validator
func NewOptionalAttributeValidator(options *OptionalAttributeOptions) *OptionalAttributeValidator {
	return &OptionalAttributeValidator{
		dictionary: options.Dictionary,
		strict:     options.Strict,
	}
}

// ValidateOptionalAttributes validates optional attributes in a packet
func (oav *OptionalAttributeValidator) ValidateOptionalAttributes(_ context.Context, req *packet.Packet) error {
	if oav.dictionary == nil {
		return nil // No dictionary available for validation
	}

	for _, attr := range req.Attributes {
		// Check if attribute is defined in dictionary
		var attrDef *dictionary.AttributeDefinition
		var found bool

		// Look in standard attributes
		if def, exists := oav.dictionary.Attributes[uint8(attr.Type)]; exists {
			attrDef = def
			found = true
		} else if attr.Type == packet.AttrVendorSpecific && len(attr.Value) >= 6 {
			// Look in VSAs if this is a vendor-specific attribute
			vendorID := uint32(attr.Value[0])<<24 | uint32(attr.Value[1])<<16 | uint32(attr.Value[2])<<8 | uint32(attr.Value[3])
			vsaType := attr.Value[5]

			if vsaMap, exists := oav.dictionary.VSAs[vendorID]; exists {
				if def, exists := vsaMap[vsaType]; exists {
					attrDef = def
					found = true
				}
			}
		}

		// If attribute is not found and we're in strict mode, reject
		if !found && oav.strict {
			return fmt.Errorf("unknown attribute type %d not allowed in strict mode", attr.Type)
		}

		// If attribute is defined and marked as optional, validate it
		if found && attrDef.Optional {
			if err := oav.validateOptionalAttribute(attr, attrDef); err != nil {
				return fmt.Errorf("optional attribute %d validation failed: %w", attr.Type, err)
			}
		}
	}

	return nil
}

// validateOptionalAttribute validates a specific optional attribute
func (oav *OptionalAttributeValidator) validateOptionalAttribute(attr packet.Attribute, attrDef *dictionary.AttributeDefinition) error {
	// Validate length constraints for optional attributes
	if attrDef.Length > 0 {
		expectedLength := attrDef.Length
		if len(attr.Value) != expectedLength {
			return fmt.Errorf("optional attribute length mismatch: expected %d, got %d", expectedLength, len(attr.Value))
		}
	}

	// Validate data type for optional attributes
	switch attrDef.DataType {
	case dictionary.DataTypeString:
		// Validate UTF-8 for string attributes
		if !isValidUTF8(attr.Value) {
			return fmt.Errorf("optional string attribute contains invalid UTF-8")
		}

	case dictionary.DataTypeInteger, dictionary.DataTypeUint32:
		if len(attr.Value) != 4 {
			return fmt.Errorf("optional integer attribute must be 4 bytes, got %d", len(attr.Value))
		}

	case dictionary.DataTypeUint64:
		if len(attr.Value) != 8 {
			return fmt.Errorf("optional uint64 attribute must be 8 bytes, got %d", len(attr.Value))
		}

	case dictionary.DataTypeIPAddr:
		if len(attr.Value) != 4 {
			return fmt.Errorf("optional ipaddr attribute must be 4 bytes, got %d", len(attr.Value))
		}

	case dictionary.DataTypeIPv6Addr:
		if len(attr.Value) != 16 {
			return fmt.Errorf("optional ipv6addr attribute must be 16 bytes, got %d", len(attr.Value))
		}

	case dictionary.DataTypeDate:
		if len(attr.Value) != 4 {
			return fmt.Errorf("optional date attribute must be 4 bytes, got %d", len(attr.Value))
		}
	}

	return nil
}

// OptionalAttributeMiddleware creates middleware for optional attribute validation
func OptionalAttributeMiddleware(options *OptionalAttributeOptions) MiddlewareHandler {
	validator := NewOptionalAttributeValidator(options)

	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Validate optional attributes
		if err := validator.ValidateOptionalAttributes(ctx, req); err != nil {
			return nil, NewHandlerError(ErrorCodeInvalidRequest, "optional attribute validation failed", err)
		}

		// Continue to next handler
		return next(ctx, clientCtx, req)
	}
}

// OptionalAttributeProcessor processes optional attributes for enhanced functionality
type OptionalAttributeProcessor struct {
	dictionary *dictionary.Dictionary
	processors map[uint8]OptionalAttributeProcessorFunc
}

// OptionalAttributeProcessorFunc defines a function for processing optional attributes
type OptionalAttributeProcessorFunc func(ctx context.Context, attr packet.Attribute, clientCtx *ClientContext) error

// NewOptionalAttributeProcessor creates a new optional attribute processor
func NewOptionalAttributeProcessor(dictionary *dictionary.Dictionary) *OptionalAttributeProcessor {
	return &OptionalAttributeProcessor{
		dictionary: dictionary,
		processors: make(map[uint8]OptionalAttributeProcessorFunc),
	}
}

// RegisterProcessor registers a processor for a specific optional attribute type
func (oap *OptionalAttributeProcessor) RegisterProcessor(attrType uint8, processor OptionalAttributeProcessorFunc) {
	oap.processors[attrType] = processor
}

// ProcessOptionalAttributes processes all optional attributes in a packet
func (oap *OptionalAttributeProcessor) ProcessOptionalAttributes(ctx context.Context, req *packet.Packet, clientCtx *ClientContext) error {
	if oap.dictionary == nil {
		return nil
	}

	for _, attr := range req.Attributes {
		// Check if this is an optional attribute
		if attrDef, exists := oap.dictionary.Attributes[uint8(attr.Type)]; exists && attrDef.Optional {
			// Check if we have a processor for this attribute
			if processor, exists := oap.processors[attr.Type]; exists {
				if err := processor(ctx, attr, clientCtx); err != nil {
					return fmt.Errorf("processing optional attribute %d failed: %w", attr.Type, err)
				}
			}
		}
	}

	return nil
}

// OptionalAttributeProcessingMiddleware creates middleware for optional attribute processing
func OptionalAttributeProcessingMiddleware(processor *OptionalAttributeProcessor) MiddlewareHandler {
	return func(ctx context.Context, clientCtx *ClientContext, req *packet.Packet, next HandlerFunc) (*HandlerResult, error) {
		// Process optional attributes
		if err := processor.ProcessOptionalAttributes(ctx, req, clientCtx); err != nil {
			return nil, NewHandlerError(ErrorCodeInvalidRequest, "optional attribute processing failed", err)
		}

		// Continue to next handler
		return next(ctx, clientCtx, req)
	}
}

// Helper function to check if bytes contain valid UTF-8
func isValidUTF8(data []byte) bool {
	for i := 0; i < len(data); {
		r, size := decodeRune(data[i:])
		if r == 0xFFFD && size == 1 {
			return false
		}
		i += size
	}
	return true
}

// Helper function to decode a UTF-8 rune (simplified version)
func decodeRune(data []byte) (rune, int) {
	if len(data) == 0 {
		return 0xFFFD, 1
	}

	b := data[0]
	if b < 0x80 {
		return rune(b), 1
	}

	if b < 0xC0 {
		return 0xFFFD, 1
	}

	if b < 0xE0 {
		if len(data) < 2 {
			return 0xFFFD, 1
		}
		return rune(b&0x1F)<<6 | rune(data[1]&0x3F), 2
	}

	if b < 0xF0 {
		if len(data) < 3 {
			return 0xFFFD, 1
		}
		return rune(b&0x0F)<<12 | rune(data[1]&0x3F)<<6 | rune(data[2]&0x3F), 3
	}

	if len(data) < 4 {
		return 0xFFFD, 1
	}
	return rune(b&0x07)<<18 | rune(data[1]&0x3F)<<12 | rune(data[2]&0x3F)<<6 | rune(data[3]&0x3F), 4
}
