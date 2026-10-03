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
//   - Cisco vendor attributes
//   - DSL Forum access-line attributes
//   - Microsoft vendor attributes
//   - F5 Networks vendor attributes
//   - A10 Networks vendor attributes
//   - Arista Networks vendor attributes
//   - Arista WiFi vendor attributes
//   - Ciena vendor attributes
//   - Benu Networks (Ciena vBNG) vendor attributes
//   - ZTE vendor attributes
//   - Huawei vendor attributes
//   - Alcatel vendor attributes
//   - Alcatel-Lucent AAA vendor attributes
//   - Alcatel-ESAM vendor attributes (format=2,1)
//   - Nokia SR (7750 SR / Timetra) vendor attributes
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

	if err := dict.AddVendor(CiscoVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(DSLForumVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(MicrosoftVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(F5VendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(A10VendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(AristaVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(AristaWiFiVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(CienaVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(BenuVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(ZTEVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(HuaweiVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(AlcatelVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(ALUAAAVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(AlcatelESAMVendorDefinition); err != nil {
		return nil, err
	}

	if err := dict.AddVendor(NokiaSRVendorDefinition); err != nil {
		return nil, err
	}

	return dict, nil
}
