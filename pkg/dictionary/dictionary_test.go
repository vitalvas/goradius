package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDictionary(t *testing.T) {
	dict := NewDictionary()

	assert.NotNil(t, dict.Vendors)
	assert.NotNil(t, dict.Attributes)
	assert.NotNil(t, dict.VSAs)
	assert.Empty(t, dict.Vendors)
	assert.Empty(t, dict.Attributes)
	assert.Empty(t, dict.VSAs)
}

func TestDictionaryAddVendor(t *testing.T) {
	dict := NewDictionary()

	tests := []struct {
		name    string
		vendor  *VendorDefinition
		wantErr bool
	}{
		{
			name: "valid vendor",
			vendor: &VendorDefinition{
				Name: "Cisco",
				ID:   9,
			},
			wantErr: false,
		},
		{
			name:    "nil vendor",
			vendor:  nil,
			wantErr: true,
		},
		{
			name: "zero ID",
			vendor: &VendorDefinition{
				Name: "Invalid",
				ID:   0,
			},
			wantErr: true,
		},
		{
			name: "empty name",
			vendor: &VendorDefinition{
				Name: "",
				ID:   10,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dict.AddVendor(tt.vendor)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.vendor, dict.Vendors[tt.vendor.ID])
			}
		})
	}

	// Test duplicate vendor ID
	vendor1 := &VendorDefinition{Name: "Vendor1", ID: 100}
	vendor2 := &VendorDefinition{Name: "Vendor2", ID: 100}

	require.NoError(t, dict.AddVendor(vendor1))
	err := dict.AddVendor(vendor2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestDictionaryAddAttribute(t *testing.T) {
	dict := NewDictionary()

	// Add a vendor for VSA testing
	vendor := &VendorDefinition{Name: "Cisco", ID: 9}
	require.NoError(t, dict.AddVendor(vendor))

	tests := []struct {
		name    string
		attr    *AttributeDefinition
		wantErr bool
	}{
		{
			name: "valid standard attribute",
			attr: &AttributeDefinition{
				Name:     "User-Name",
				ID:       1,
				DataType: DataTypeString,
			},
			wantErr: false,
		},
		{
			name: "valid VSA",
			attr: &AttributeDefinition{
				Name:     "Cisco-AVPair",
				ID:       1,
				DataType: DataTypeString,
				VendorID: 9,
			},
			wantErr: false,
		},
		{
			name:    "nil attribute",
			attr:    nil,
			wantErr: true,
		},
		{
			name: "empty name",
			attr: &AttributeDefinition{
				Name:     "",
				ID:       2,
				DataType: DataTypeString,
			},
			wantErr: true,
		},
		{
			name: "invalid data type",
			attr: &AttributeDefinition{
				Name:     "Invalid-Attr",
				ID:       3,
				DataType: "invalid",
			},
			wantErr: true,
		},
		{
			name: "VSA with unknown vendor",
			attr: &AttributeDefinition{
				Name:     "Unknown-VSA",
				ID:       1,
				DataType: DataTypeString,
				VendorID: 999,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dict.AddAttribute(tt.attr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.attr.VendorID == 0 {
					assert.Equal(t, tt.attr, dict.Attributes[tt.attr.ID])
				} else {
					assert.Equal(t, tt.attr, dict.VSAs[tt.attr.VendorID][tt.attr.ID])
				}
			}
		})
	}
}

func TestDictionaryGet(t *testing.T) {
	dict := NewDictionary()

	// Add vendor and attributes
	vendor := &VendorDefinition{Name: "Cisco", ID: 9}
	require.NoError(t, dict.AddVendor(vendor))

	stdAttr := &AttributeDefinition{
		Name:     "User-Name",
		ID:       1,
		DataType: DataTypeString,
	}
	require.NoError(t, dict.AddAttribute(stdAttr))

	vsaAttr := &AttributeDefinition{
		Name:     "Cisco-AVPair",
		ID:       1,
		DataType: DataTypeString,
		VendorID: 9,
	}
	require.NoError(t, dict.AddAttribute(vsaAttr))

	// Test GetAttribute
	attr, exists := dict.GetAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, stdAttr, attr)

	_, exists = dict.GetAttribute(99)
	assert.False(t, exists)

	// Test GetVSA
	vsa, exists := dict.GetVSA(9, 1)
	assert.True(t, exists)
	assert.Equal(t, vsaAttr, vsa)

	_, exists = dict.GetVSA(9, 99)
	assert.False(t, exists)

	_, exists = dict.GetVSA(99, 1)
	assert.False(t, exists)

	// Test GetVendor
	v, exists := dict.GetVendor(9)
	assert.True(t, exists)
	assert.Equal(t, vendor, v)

	_, exists = dict.GetVendor(99)
	assert.False(t, exists)

	// Test GetAttributeByName
	attr, exists = dict.GetAttributeByName("User-Name")
	assert.True(t, exists)
	assert.Equal(t, stdAttr, attr)

	attr, exists = dict.GetAttributeByName("Cisco-AVPair")
	assert.True(t, exists)
	assert.Equal(t, vsaAttr, attr)

	_, exists = dict.GetAttributeByName("Non-Existent")
	assert.False(t, exists)
}

func TestAttributeDefinitionMethods(t *testing.T) {
	// Test fixed length
	fixedAttr := &AttributeDefinition{
		Name:     "Fixed-Attr",
		ID:       1,
		DataType: DataTypeString,
		Length:   10,
	}

	assert.True(t, fixedAttr.IsFixedLength())
	assert.Equal(t, 10, fixedAttr.GetFixedLength())

	variableAttr := &AttributeDefinition{
		Name:     "Variable-Attr",
		ID:       2,
		DataType: DataTypeString,
	}

	assert.False(t, variableAttr.IsFixedLength())
	assert.Equal(t, 0, variableAttr.GetFixedLength())

	// Test values
	attrWithValues := &AttributeDefinition{
		Name:     "Service-Type",
		ID:       6,
		DataType: DataTypeInteger,
		Values: map[string]uint32{
			"Login":    1,
			"Framed":   2,
			"Callback": 3,
		},
	}

	assert.True(t, attrWithValues.HasValues())
	assert.Equal(t, "Login", attrWithValues.GetValueName(1))
	assert.Equal(t, "Framed", attrWithValues.GetValueName(2))
	assert.Equal(t, "", attrWithValues.GetValueName(99))

	value, exists := attrWithValues.GetValueByName("Login")
	assert.True(t, exists)
	assert.Equal(t, uint32(1), value)

	value, exists = attrWithValues.GetValueByName("Callback")
	assert.True(t, exists)
	assert.Equal(t, uint32(3), value)

	_, exists = attrWithValues.GetValueByName("Non-Existent")
	assert.False(t, exists)

	attrWithoutValues := &AttributeDefinition{
		Name:     "User-Name",
		ID:       1,
		DataType: DataTypeString,
	}

	assert.False(t, attrWithoutValues.HasValues())
}

func TestAttributeValidateValue(t *testing.T) {
	tests := []struct {
		name    string
		attr    *AttributeDefinition
		value   []byte
		wantErr bool
	}{
		{
			name: "valid string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
			},
			value:   []byte("test"),
			wantErr: false,
		},
		{
			name: "valid fixed-length string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   4,
			},
			value:   []byte("test"),
			wantErr: false,
		},
		{
			name: "invalid fixed-length string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   4,
			},
			value:   []byte("toolong"),
			wantErr: true,
		},
		{
			name: "valid integer",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
			},
			value:   []byte{0x00, 0x00, 0x00, 0x01},
			wantErr: false,
		},
		{
			name: "invalid integer length",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
			},
			value:   []byte{0x00, 0x01},
			wantErr: true,
		},
		{
			name: "valid uint64",
			attr: &AttributeDefinition{
				DataType: DataTypeUint64,
			},
			value:   []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantErr: false,
		},
		{
			name: "invalid uint64 length",
			attr: &AttributeDefinition{
				DataType: DataTypeUint64,
			},
			value:   []byte{0x00, 0x00, 0x00, 0x01},
			wantErr: true,
		},
		{
			name: "valid IP address",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
			},
			value:   []byte{192, 168, 1, 1},
			wantErr: false,
		},
		{
			name: "invalid IP address length",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
			},
			value:   []byte{192, 168},
			wantErr: true,
		},
		{
			name: "valid IPv6 address",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Addr,
			},
			value:   make([]byte, 16),
			wantErr: false,
		},
		{
			name: "invalid IPv6 address length",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Addr,
			},
			value:   make([]byte, 8),
			wantErr: true,
		},
		{
			name: "valid IPv6 prefix",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Prefix,
			},
			value:   []byte{64, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00}, // /64 prefix
			wantErr: false,
		},
		{
			name: "invalid IPv6 prefix length too short",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Prefix,
			},
			value:   []byte{64}, // Missing prefix bytes
			wantErr: true,
		},
		{
			name: "invalid IPv6 prefix length value",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Prefix,
			},
			value:   []byte{200, 0x20, 0x01}, // Prefix length > 128
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attr.ValidateValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAttributeParseValue(t *testing.T) {
	tests := []struct {
		name     string
		attr     *AttributeDefinition
		valueStr string
		expected []byte
		wantErr  bool
	}{
		{
			name: "string value",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
			},
			valueStr: "testuser",
			expected: []byte("testuser"),
		},
		{
			name: "hex octets",
			attr: &AttributeDefinition{
				DataType: DataTypeOctets,
			},
			valueStr: "0x01020304",
			expected: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "plain octets",
			attr: &AttributeDefinition{
				DataType: DataTypeOctets,
			},
			valueStr: "test",
			expected: []byte("test"),
		},
		{
			name: "integer value",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
			},
			valueStr: "1234567890",
			expected: []byte{0x49, 0x96, 0x02, 0xD2},
		},
		{
			name: "uint64 value",
			attr: &AttributeDefinition{
				DataType: DataTypeUint64,
			},
			valueStr: "1234567890123456789",
			expected: []byte{0x11, 0x22, 0x10, 0xF4, 0x7D, 0xE9, 0x81, 0x15},
		},
		{
			name: "date unix timestamp",
			attr: &AttributeDefinition{
				DataType: DataTypeDate,
			},
			valueStr: "1609459200",
			expected: []byte{0x5F, 0xEE, 0x66, 0x00},
		},
		{
			name: "IPv4 address",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
			},
			valueStr: "192.168.1.1",
			expected: []byte{192, 168, 1, 1},
		},
		{
			name: "IPv6 address",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Addr,
			},
			valueStr: "2001:db8::1",
			expected: []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
		},
		{
			name: "IPv6 prefix /64",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Prefix,
			},
			valueStr: "2001:db8::/64",
			expected: []byte{64, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00}, // /64 requires 8 bytes
		},
		{
			name: "IPv6 prefix /48",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Prefix,
			},
			valueStr: "2001:db8::/48",
			expected: []byte{48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00}, // /48 requires 6 bytes
		},
		{
			name: "IPv6 prefix /128",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Prefix,
			},
			valueStr: "2001:db8::1/128",
			expected: []byte{128, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}, // /128 requires all 16 bytes
		},
		{
			name: "invalid integer",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
			},
			valueStr: "not-a-number",
			wantErr:  true,
		},
		{
			name: "invalid IP address",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
			},
			valueStr: "300.300.300.300",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.attr.ParseValue(tt.valueStr)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestAttributeDefinitionTaggedSupport(t *testing.T) {
	t.Run("tagged attribute", func(t *testing.T) {
		attr := &AttributeDefinition{
			Name:     "Tunnel-Type",
			ID:       64,
			DataType: DataTypeInteger,
			HasTag:   true,
		}

		assert.True(t, attr.IsTagged())
	})

	t.Run("non-tagged attribute", func(t *testing.T) {
		attr := &AttributeDefinition{
			Name:     "User-Name",
			ID:       1,
			DataType: DataTypeString,
		}

		assert.False(t, attr.IsTagged())
	})
}

func TestAttributeValidateValueTagged(t *testing.T) {
	tests := []struct {
		name     string
		attr     *AttributeDefinition
		value    []byte
		wantErr  bool
		errorMsg string
	}{
		{
			name: "valid tagged string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
			},
			value:   []byte{0x01, 't', 'e', 's', 't'},
			wantErr: false,
		},
		{
			name: "valid tagged integer",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
				HasTag:   true,
			},
			value:   []byte{0x05, 0x00, 0x00, 0x00, 0x42},
			wantErr: false,
		},
		{
			name: "tagged attribute with minimum tag",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
			},
			value:   []byte{0x01, 't', 'e', 's', 't'},
			wantErr: false,
		},
		{
			name: "tagged attribute with maximum tag",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
			},
			value:   []byte{0x1F, 't', 'e', 's', 't'},
			wantErr: false,
		},
		{
			name: "tagged attribute with empty value",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
			},
			value:    []byte{},
			wantErr:  true,
			errorMsg: "tagged attribute cannot be empty",
		},
		{
			name: "tagged attribute with invalid tag 0x00",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
			},
			value:    []byte{0x00, 't', 'e', 's', 't'},
			wantErr:  true,
			errorMsg: "invalid tag value",
		},
		{
			name: "tagged attribute with invalid tag 0x20",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
			},
			value:    []byte{0x20, 't', 'e', 's', 't'},
			wantErr:  true,
			errorMsg: "invalid tag value",
		},
		{
			name: "tagged fixed-length attribute",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
				Length:   5, // 1 byte tag + 4 bytes value
			},
			value:   []byte{0x01, 't', 'e', 's', 't'},
			wantErr: false,
		},
		{
			name: "tagged fixed-length attribute wrong length",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
				Length:   5, // 1 byte tag + 4 bytes value
			},
			value:    []byte{0x01, 't', 'e', 's', 't', 'x'}, // Too long
			wantErr:  true,
			errorMsg: "does not match required length",
		},
		{
			name: "tagged integer with correct length",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
				HasTag:   true,
			},
			value:   []byte{0x05, 0x12, 0x34, 0x56, 0x78},
			wantErr: false,
		},
		{
			name: "tagged integer with wrong length",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
				HasTag:   true,
			},
			value:    []byte{0x05, 0x12, 0x34}, // Too short
			wantErr:  true,
			errorMsg: "integer value must be 4 bytes",
		},
		{
			name: "tagged IP address",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
				HasTag:   true,
			},
			value:   []byte{0x01, 192, 168, 1, 1},
			wantErr: false,
		},
		{
			name: "tagged IP address wrong length",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
				HasTag:   true,
			},
			value:    []byte{0x01, 192, 168}, // Too short
			wantErr:  true,
			errorMsg: "IP address must be 4 bytes",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attr.ValidateValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAttributeParseValueTagged(t *testing.T) {
	tests := []struct {
		name     string
		attr     *AttributeDefinition
		valueStr string
		tag      uint8
		wantErr  bool
	}{
		{
			name: "tagged string value",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				HasTag:   true,
			},
			valueStr: "test",
			tag:      0x01,
			wantErr:  false,
		},
		{
			name: "tagged integer value",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
				HasTag:   true,
			},
			valueStr: "42",
			tag:      0x05,
			wantErr:  false,
		},
		{
			name: "tagged IP address value",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
				HasTag:   true,
			},
			valueStr: "192.168.1.1",
			tag:      0x10,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse the base value
			baseValue, err := tt.attr.ParseValue(tt.valueStr)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)

			// Create tagged value by prepending tag
			taggedValue := make([]byte, 1+len(baseValue))
			taggedValue[0] = tt.tag
			copy(taggedValue[1:], baseValue)

			// Validate tagged value
			err = tt.attr.ValidateValue(taggedValue)
			assert.NoError(t, err)
		})
	}
}

func TestDictionaryTaggedAttributeIntegration(t *testing.T) {
	dict := NewDictionary()

	// Add tagged attributes
	tunnelType := &AttributeDefinition{
		Name:     "Tunnel-Type",
		ID:       64,
		DataType: DataTypeInteger,
		HasTag:   true,
	}

	tunnelEndpoint := &AttributeDefinition{
		Name:     "Tunnel-Client-Endpoint",
		ID:       66,
		DataType: DataTypeString,
		HasTag:   true,
	}

	err := dict.AddAttribute(tunnelType)
	require.NoError(t, err)

	err = dict.AddAttribute(tunnelEndpoint)
	require.NoError(t, err)

	t.Run("retrieve tagged attributes", func(t *testing.T) {
		attr, exists := dict.GetAttribute(64)
		require.True(t, exists)
		assert.Equal(t, "Tunnel-Type", attr.Name)
		assert.True(t, attr.IsTagged())

		attr, exists = dict.GetAttribute(66)
		require.True(t, exists)
		assert.Equal(t, "Tunnel-Client-Endpoint", attr.Name)
		assert.True(t, attr.IsTagged())
	})

	t.Run("validate tagged attribute values", func(t *testing.T) {
		attr, _ := dict.GetAttribute(64)

		// Valid tagged integer
		err := attr.ValidateValue([]byte{0x01, 0x00, 0x00, 0x00, 0x05})
		assert.NoError(t, err)

		// Invalid tag
		err = attr.ValidateValue([]byte{0x00, 0x00, 0x00, 0x00, 0x05})
		assert.Error(t, err)

		// Invalid length
		err = attr.ValidateValue([]byte{0x01, 0x00, 0x00})
		assert.Error(t, err)
	})

	t.Run("tagged attribute by name lookup", func(t *testing.T) {
		attr, exists := dict.GetAttributeByName("Tunnel-Type")
		require.True(t, exists)
		assert.Equal(t, uint8(64), attr.ID)
		assert.True(t, attr.IsTagged())

		attr, exists = dict.GetAttributeByName("Tunnel-Client-Endpoint")
		require.True(t, exists)
		assert.Equal(t, uint8(66), attr.ID)
		assert.True(t, attr.IsTagged())
	})
}

func TestTaggedAttributeRealWorldScenarios(t *testing.T) {
	dict := NewDictionary()

	// Add ERX-Service-Activate as mentioned in the original request
	erxServiceActivate := &AttributeDefinition{
		Name:     "ERX-Service-Activate",
		ID:       65,
		DataType: DataTypeString,
		HasTag:   true,
	}

	err := dict.AddAttribute(erxServiceActivate)
	require.NoError(t, err)

	t.Run("ERX-Service-Activate tagged attribute", func(t *testing.T) {
		attr, exists := dict.GetAttribute(65)
		require.True(t, exists)
		assert.Equal(t, "ERX-Service-Activate", attr.Name)
		assert.True(t, attr.IsTagged())

		// Test with various tag values and service names
		testCases := []struct {
			tag     uint8
			service string
		}{
			{0x01, "service1"},
			{0x05, "premium-service"},
			{0x1F, "max-tag-service"},
			{0x10, ""},
		}

		for _, tc := range testCases {
			value := make([]byte, 1+len(tc.service))
			value[0] = tc.tag
			copy(value[1:], tc.service)

			err := attr.ValidateValue(value)
			assert.NoError(t, err, "Tag %d with service '%s' should be valid", tc.tag, tc.service)
		}

		// Test invalid tags
		invalidTags := []uint8{0x00, 0x20, 0x30, 0xFF}
		for _, tag := range invalidTags {
			value := []byte{tag, 't', 'e', 's', 't'}
			err := attr.ValidateValue(value)
			assert.Error(t, err, "Tag %d should be invalid", tag)
		}
	})
}

func TestTaggedAttributeEdgeCases(t *testing.T) {
	attr := &AttributeDefinition{
		Name:     "Tunnel-Type",
		ID:       64,
		DataType: DataTypeInteger,
		HasTag:   true,
	}

	t.Run("tagged attribute with just tag byte", func(t *testing.T) {
		// Only tag byte, no value
		err := attr.ValidateValue([]byte{0x01})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "integer value must be 4 bytes")
	})

	t.Run("tagged attribute with maximum valid tag", func(t *testing.T) {
		err := attr.ValidateValue([]byte{0x1F, 0x00, 0x00, 0x00, 0x01})
		assert.NoError(t, err)
	})

	t.Run("tagged attribute with minimum valid tag", func(t *testing.T) {
		err := attr.ValidateValue([]byte{0x01, 0x00, 0x00, 0x00, 0x01})
		assert.NoError(t, err)
	})

	t.Run("tagged string attribute with empty value", func(t *testing.T) {
		stringAttr := &AttributeDefinition{
			Name:     "Tunnel-Client-Endpoint",
			ID:       66,
			DataType: DataTypeString,
			HasTag:   true,
		}

		// Tag with empty string value is valid
		err := stringAttr.ValidateValue([]byte{0x01})
		assert.NoError(t, err)
	})
}

func TestDictionary_AddVSA(t *testing.T) {
	dict := NewDictionary()

	// Add vendor first
	vendor := &VendorDefinition{
		ID:   9,
		Name: "Cisco",
	}
	err := dict.AddVendor(vendor)
	require.NoError(t, err)

	vsa := &AttributeDefinition{
		Name:     "Test-VSA",
		ID:       1,
		DataType: DataTypeString,
		VendorID: 9,
	}

	err = dict.AddAttribute(vsa)
	assert.NoError(t, err)

	// Test duplicate VSA
	err = dict.AddAttribute(vsa)
	assert.Error(t, err)

	// Test VSA without vendor
	vsaNoVendor := &AttributeDefinition{
		Name:     "Test-VSA-No-Vendor",
		ID:       2,
		DataType: DataTypeString,
		VendorID: 999,
	}
	err = dict.AddAttribute(vsaNoVendor)
	assert.Error(t, err)
}

func TestDictionary_Helper_Functions(t *testing.T) {
	// Test parseHexString without 0x prefix
	result, err := parseHexString("41424344")
	assert.NoError(t, err)
	assert.Equal(t, []byte{0x41, 0x42, 0x43, 0x44}, result)

	// Test invalid hex string
	_, err = parseHexString("invalid")
	assert.Error(t, err)

	// Test uint32ToBytes
	bytes := uint32ToBytes(0x41424344)
	assert.Equal(t, []byte{0x41, 0x42, 0x43, 0x44}, bytes)

	// Test uint64ToBytes
	bytes64 := uint64ToBytes(0x4142434445464748)
	assert.Equal(t, []byte{0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48}, bytes64)

	// Test isValidUTF8
	assert.True(t, isValidUTF8([]byte("test")))
	assert.True(t, isValidUTF8([]byte("тест"))) // Cyrillic test
	assert.False(t, isValidUTF8([]byte{0xff, 0xfe, 0xfd}))

	// Test edge cases for isValidUTF8
	assert.True(t, isValidUTF8([]byte{}))            // empty
	assert.True(t, isValidUTF8([]byte("Hello, 世界"))) // Unicode
}

func TestAttributeDefinition_DataTypeValidation(t *testing.T) {
	// Test using AttributeDefinition.ValidateValue instead of private function
	tests := []struct {
		dataType DataType
		value    []byte
		wantErr  bool
	}{
		{DataTypeString, []byte("test"), false},
		{DataTypeInteger, []byte{0x00, 0x00, 0x00, 0x01}, false},
		{DataTypeInteger, []byte("test"), false}, // ValidateValue doesn't validate data type format
		{DataTypeIPAddr, []byte{192, 168, 1, 1}, false},
		{DataTypeIPAddr, []byte{192, 168}, true},
		{DataTypeDate, []byte{0x5F, 0xEE, 0x66, 0x00}, false},
		{DataTypeDate, []byte{0x5F, 0xEE}, true},
	}

	for _, tt := range tests {
		attr := &AttributeDefinition{
			Name:     "Test",
			ID:       1,
			DataType: tt.dataType,
		}
		err := attr.ValidateValue(tt.value)
		if tt.wantErr {
			assert.Error(t, err)
		} else {
			assert.NoError(t, err)
		}
	}
}

func TestEncryptionType_ParseEncryptionType(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected EncryptionType
		wantErr  bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: EncryptionNone,
			wantErr:  false,
		},
		{
			name:     "numeric format 1",
			input:    "1",
			expected: EncryptionUserPassword,
			wantErr:  false,
		},
		{
			name:     "numeric format 2",
			input:    "2",
			expected: EncryptionTunnelPassword,
			wantErr:  false,
		},
		{
			name:     "numeric format 3",
			input:    "3",
			expected: EncryptionAscendSecret,
			wantErr:  false,
		},
		{
			name:     "string format User-Password",
			input:    "User-Password",
			expected: EncryptionUserPassword,
			wantErr:  false,
		},
		{
			name:     "string format Tunnel-Password",
			input:    "Tunnel-Password",
			expected: EncryptionTunnelPassword,
			wantErr:  false,
		},
		{
			name:     "string format Ascend-Secret",
			input:    "Ascend-Secret",
			expected: EncryptionAscendSecret,
			wantErr:  false,
		},
		{
			name:     "invalid format",
			input:    "invalid",
			expected: EncryptionNone,
			wantErr:  true,
		},
		{
			name:     "invalid numeric",
			input:    "4",
			expected: EncryptionNone,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseEncryptionType(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestEncryptionType_ToNumeric(t *testing.T) {
	tests := []struct {
		encType  EncryptionType
		expected string
	}{
		{EncryptionNone, ""},
		{EncryptionUserPassword, "1"},
		{EncryptionTunnelPassword, "2"},
		{EncryptionAscendSecret, "3"},
	}

	for _, tt := range tests {
		t.Run(string(tt.encType), func(t *testing.T) {
			result := tt.encType.ToNumeric()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEncryptionType_String(t *testing.T) {
	tests := []struct {
		encType  EncryptionType
		expected string
	}{
		{EncryptionNone, ""},
		{EncryptionUserPassword, "User-Password"},
		{EncryptionTunnelPassword, "Tunnel-Password"},
		{EncryptionAscendSecret, "Ascend-Secret"},
	}

	for _, tt := range tests {
		t.Run(string(tt.encType), func(t *testing.T) {
			result := tt.encType.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEncryptionType_IsValid(t *testing.T) {
	tests := []struct {
		encType EncryptionType
		valid   bool
	}{
		{EncryptionNone, true},
		{EncryptionUserPassword, true},
		{EncryptionTunnelPassword, true},
		{EncryptionAscendSecret, true},
		{EncryptionType("invalid"), false},
		{EncryptionType("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.encType), func(t *testing.T) {
			result := tt.encType.IsValid()
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestAttributeDefinition_EncryptionMethods(t *testing.T) {
	tests := []struct {
		name            string
		encryption      EncryptionType
		expectEncrypted bool
	}{
		{
			name:            "no encryption",
			encryption:      EncryptionNone,
			expectEncrypted: false,
		},
		{
			name:            "empty encryption",
			encryption:      "",
			expectEncrypted: false,
		},
		{
			name:            "User-Password encryption",
			encryption:      EncryptionUserPassword,
			expectEncrypted: true,
		},
		{
			name:            "Tunnel-Password encryption",
			encryption:      EncryptionTunnelPassword,
			expectEncrypted: true,
		},
		{
			name:            "Ascend-Secret encryption",
			encryption:      EncryptionAscendSecret,
			expectEncrypted: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := &AttributeDefinition{
				Name:       "Test-Attr",
				ID:         1,
				DataType:   DataTypeString,
				Encryption: tt.encryption,
			}

			assert.Equal(t, tt.expectEncrypted, attr.IsEncrypted())
			assert.Equal(t, tt.encryption, attr.GetEncryptionType())
		})
	}
}

func TestDictionary_EncryptionValidation(t *testing.T) {
	dict := NewDictionary()

	tests := []struct {
		name    string
		attr    *AttributeDefinition
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid encrypted string attribute",
			attr: &AttributeDefinition{
				Name:       "Test-Password",
				ID:         1,
				DataType:   DataTypeString,
				Encryption: EncryptionUserPassword,
			},
			wantErr: false,
		},
		{
			name: "valid encrypted octets attribute",
			attr: &AttributeDefinition{
				Name:       "Test-Secret",
				ID:         2,
				DataType:   DataTypeOctets,
				Encryption: EncryptionTunnelPassword,
			},
			wantErr: false,
		},
		{
			name: "valid encryption on integer",
			attr: &AttributeDefinition{
				Name:       "Test-Integer",
				ID:         3,
				DataType:   DataTypeInteger,
				Encryption: EncryptionUserPassword,
			},
			wantErr: false,
		},
		{
			name: "invalid encryption type",
			attr: &AttributeDefinition{
				Name:       "Test-Invalid",
				ID:         4,
				DataType:   DataTypeString,
				Encryption: EncryptionType("invalid"),
			},
			wantErr: true,
			errMsg:  "unsupported encryption type: invalid",
		},
		{
			name: "no encryption is valid",
			attr: &AttributeDefinition{
				Name:       "Test-Plain",
				ID:         5,
				DataType:   DataTypeString,
				Encryption: EncryptionNone,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := dict.AddAttribute(tt.attr)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAttributeDefinition_IPv6Prefix(t *testing.T) {
	tests := []struct {
		name     string
		prefix   string
		expected []byte
		wantErr  bool
	}{
		{
			name:     "IPv6 prefix /64",
			prefix:   "2001:db8::/64",
			expected: []byte{64, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00},
			wantErr:  false,
		},
		{
			name:     "IPv6 prefix /48",
			prefix:   "2001:db8::/48",
			expected: []byte{48, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00},
			wantErr:  false,
		},
		{
			name:     "IPv6 prefix /32",
			prefix:   "2001:db8::/32",
			expected: []byte{32, 0x20, 0x01, 0x0d, 0xb8},
			wantErr:  false,
		},
		{
			name:     "IPv6 prefix /128",
			prefix:   "2001:db8::1/128",
			expected: []byte{128, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			wantErr:  false,
		},
		{
			name:     "IPv6 prefix /0",
			prefix:   "::/0",
			expected: []byte{0, 0x00},
			wantErr:  false,
		},
		{
			name:    "invalid prefix format",
			prefix:  "not-a-prefix",
			wantErr: true,
		},
		{
			name:    "IPv4 prefix",
			prefix:  "192.168.1.0/24",
			wantErr: true,
		},
	}

	attr := &AttributeDefinition{
		Name:     "Test-IPv6-Prefix",
		ID:       1,
		DataType: DataTypeIPv6Prefix,
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := attr.ParseValue(tt.prefix)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)

				// Also test validation
				err = attr.ValidateValue(result)
				assert.NoError(t, err)
			}
		})
	}
}

func TestAttributeDefinition_IPv6PrefixValidation(t *testing.T) {
	attr := &AttributeDefinition{
		Name:     "Test-IPv6-Prefix",
		ID:       1,
		DataType: DataTypeIPv6Prefix,
	}

	tests := []struct {
		name    string
		value   []byte
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid prefix",
			value:   []byte{64, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00},
			wantErr: false,
		},
		{
			name:    "too short",
			value:   []byte{64},
			wantErr: true,
			errMsg:  "IPv6 prefix must be between 2 and 18 bytes",
		},
		{
			name:    "too long",
			value:   make([]byte, 19),
			wantErr: true,
			errMsg:  "IPv6 prefix must be between 2 and 18 bytes",
		},
		{
			name:    "invalid prefix length",
			value:   []byte{200, 0x20, 0x01},
			wantErr: true,
			errMsg:  "IPv6 prefix length must be 0-128",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := attr.ValidateValue(tt.value)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDictionary_IPv6PrefixDataType(t *testing.T) {
	dict := NewDictionary()

	// Test adding IPv6 prefix attribute
	attr := &AttributeDefinition{
		Name:     "Test-IPv6-Prefix",
		ID:       1,
		DataType: DataTypeIPv6Prefix,
	}

	err := dict.AddAttribute(attr)
	assert.NoError(t, err)

	// Test retrieving the attribute
	retrieved, exists := dict.GetAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, DataTypeIPv6Prefix, retrieved.DataType)

	// Test with length constraint
	attrWithLength := &AttributeDefinition{
		Name:     "Test-IPv6-Prefix-Fixed",
		ID:       2,
		DataType: DataTypeIPv6Prefix,
		Length:   9, // Valid length for /64 prefix
	}

	err = dict.AddAttribute(attrWithLength)
	assert.NoError(t, err)

	// Test with invalid length constraint
	attrInvalidLength := &AttributeDefinition{
		Name:     "Test-IPv6-Prefix-Invalid",
		ID:       3,
		DataType: DataTypeIPv6Prefix,
		Length:   1, // Too short
	}

	err = dict.AddAttribute(attrInvalidLength)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ipv6prefix attributes must be between 2 and 18 bytes")
}

func TestDictionary_EncryptionIntegration(t *testing.T) {
	dict := NewDictionary()

	// Add attributes with different encryption types
	userPasswordAttr := &AttributeDefinition{
		Name:       "User-Password",
		ID:         2,
		DataType:   DataTypeString,
		Encryption: EncryptionUserPassword,
	}

	tunnelPasswordAttr := &AttributeDefinition{
		Name:       "Tunnel-Password",
		ID:         69,
		DataType:   DataTypeString,
		Encryption: EncryptionTunnelPassword,
		HasTag:     true,
	}

	plainTextAttr := &AttributeDefinition{
		Name:     "User-Name",
		ID:       1,
		DataType: DataTypeString,
	}

	require.NoError(t, dict.AddAttribute(userPasswordAttr))
	require.NoError(t, dict.AddAttribute(tunnelPasswordAttr))
	require.NoError(t, dict.AddAttribute(plainTextAttr))

	// Test retrieval and encryption flags
	attr, exists := dict.GetAttribute(2)
	assert.True(t, exists)
	assert.Equal(t, "User-Password", attr.Name)
	assert.True(t, attr.IsEncrypted())
	assert.Equal(t, EncryptionUserPassword, attr.GetEncryptionType())

	attr, exists = dict.GetAttribute(69)
	assert.True(t, exists)
	assert.Equal(t, "Tunnel-Password", attr.Name)
	assert.True(t, attr.IsEncrypted())
	assert.True(t, attr.IsTagged())
	assert.Equal(t, EncryptionTunnelPassword, attr.GetEncryptionType())

	attr, exists = dict.GetAttribute(1)
	assert.True(t, exists)
	assert.Equal(t, "User-Name", attr.Name)
	assert.False(t, attr.IsEncrypted())
	assert.Equal(t, EncryptionNone, attr.GetEncryptionType())
}
