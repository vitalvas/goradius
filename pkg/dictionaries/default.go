package dictionaries

import "github.com/vitalvas/goradius/pkg/dictionary"

// NewDefault creates a dictionary pre-loaded with all standard RFC attributes and common vendor dictionaries.
// This is a convenience function for users who want standard RADIUS support without manually adding dictionaries.
// Currently includes:
//   - RFC 2865/2866/2868/2869 standard attributes
//   - Juniper ERX vendor attributes
//   - Ascend vendor attributes
//
// Example usage:
//
//	dict := dictionaries.NewDefault()
//	srv, err := server.New(":1812", handler, dict)
func NewDefault() *dictionary.Dictionary {
	dict := dictionary.New()
	dict.AddStandardAttributes(StandardRFCAttributes)
	dict.AddVendor(ERXVendorDefinition)
	dict.AddVendor(AscendVendorDefinition)
	return dict
}
