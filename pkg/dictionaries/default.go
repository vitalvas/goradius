package dictionaries

import "github.com/vitalvas/goradius/pkg/dictionary"

// NewDefault creates a dictionary pre-loaded with all standard RFC attributes and common vendor dictionaries.
// This is a convenience function for users who want standard RADIUS support without manually adding dictionaries.
// Currently includes:
//   - RFC 2865/2866/2868/2869 standard attributes
//   - Juniper ERX vendor attributes
//   - Ascend vendor attributes
//   - WISPr vendor attributes
//   - Mikrotik vendor attributes
//
// Returns an error if there are duplicate attribute names, which would indicate a programming error
// in the dictionary definitions.
//
// Example usage:
//
//	dict, err := dictionaries.NewDefault()
//	if err != nil {
//		return err
//	}
//	srv, err := server.New(":1812", handler, dict)
func NewDefault() (*dictionary.Dictionary, error) {
	dict := dictionary.New()

	if err := dict.AddStandardAttributes(StandardRFCAttributes); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(ERXVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(AscendVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(WISPrVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(MikrotikVendorDefinition); err != nil {
		return nil, err
	}

	return dict, nil
}
