package goradius

// NewDefault creates a dictionary pre-loaded with all standard RFC attributes and common vendor
// This is a convenience function for users who want standard RADIUS support without manually adding
// Currently includes:
//   - RFC 2865/2866/2868/2869 standard attributes
//   - Juniper vendor attributes
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
//	dict, err := NewDefault()
//	if err != nil {
//		return err
//	}
//	srv, err := server.NewServer(":1812", handler, dict)
func NewDefault() (*Dictionary, error) {
	dict := NewDictionary()

	if err := dict.AddStandardAttributes(StandardRFCAttributes); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(JuniperVendorDefinition); err != nil {
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
