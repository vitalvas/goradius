package packet

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAttribute(t *testing.T) {
	value := []byte("testvalue")
	attr := NewAttribute(AttrUserName, value)

	assert.Equal(t, AttrUserName, attr.Type)
	assert.Equal(t, uint8(2+len(value)), attr.Length)
	assert.Equal(t, value, attr.Value)
}

func TestNewStringAttribute(t *testing.T) {
	value := "testuser"
	attr := NewStringAttribute(AttrUserName, value)

	assert.Equal(t, AttrUserName, attr.Type)
	assert.Equal(t, uint8(2+len(value)), attr.Length)
	assert.Equal(t, []byte(value), attr.Value)
}

func TestNewIntegerAttribute(t *testing.T) {
	value := uint32(0x12345678)
	attr := NewIntegerAttribute(AttrServiceType, value)

	assert.Equal(t, AttrServiceType, attr.Type)
	assert.Equal(t, uint8(6), attr.Length) // 2 + 4 bytes

	expected := []byte{0x12, 0x34, 0x56, 0x78}
	assert.Equal(t, expected, attr.Value)
}

func TestNewIPAddressAttribute(t *testing.T) {
	ip := [4]byte{192, 168, 1, 1}
	attr := NewIPAddressAttribute(AttrNASIPAddress, ip)

	assert.Equal(t, AttrNASIPAddress, attr.Type)
	assert.Equal(t, uint8(6), attr.Length) // 2 + 4 bytes
	assert.Equal(t, ip[:], attr.Value)
}

func TestAttributeGetString(t *testing.T) {
	value := "testuser"
	attr := NewStringAttribute(AttrUserName, value)

	assert.Equal(t, value, attr.GetString())
}

func TestAttributeGetInteger(t *testing.T) {
	tests := []struct {
		name      string
		value     []byte
		expected  uint32
		expectErr bool
	}{
		{
			name:     "valid integer",
			value:    []byte{0x12, 0x34, 0x56, 0x78},
			expected: 0x12345678,
		},
		{
			name:      "invalid length",
			value:     []byte{0x12, 0x34},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := NewAttribute(AttrServiceType, tt.value)
			result, err := attr.GetInteger()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestAttributeGetIPAddress(t *testing.T) {
	tests := []struct {
		name      string
		value     []byte
		expected  [4]byte
		expectErr bool
	}{
		{
			name:     "valid IP",
			value:    []byte{192, 168, 1, 1},
			expected: [4]byte{192, 168, 1, 1},
		},
		{
			name:      "invalid length",
			value:     []byte{192, 168},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := NewAttribute(AttrNASIPAddress, tt.value)
			result, err := attr.GetIPAddress()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestAttributeGetBytes(t *testing.T) {
	value := []byte{0x01, 0x02, 0x03, 0x04}
	attr := NewAttribute(AttrClass, value)

	assert.Equal(t, value, attr.GetBytes())
}

func TestAttributeValidate(t *testing.T) {
	tests := []struct {
		name      string
		attr      Attribute
		expectErr bool
	}{
		{
			name: "valid attribute",
			attr: NewStringAttribute(AttrUserName, "testuser"),
		},
		{
			name: "length too small",
			attr: Attribute{
				Type:   AttrUserName,
				Length: 1,
				Value:  []byte("test"),
			},
			expectErr: true,
		},
		{
			name: "length mismatch",
			attr: Attribute{
				Type:   AttrUserName,
				Length: 10,
				Value:  []byte("test"),
			},
			expectErr: true,
		},
		{
			name: "valid User-Password",
			attr: Attribute{
				Type:   AttrUserPassword,
				Length: 18,
				Value:  make([]byte, 16),
			},
		},
		{
			name: "invalid User-Password length",
			attr: Attribute{
				Type:   AttrUserPassword,
				Length: 10,
				Value:  make([]byte, 8),
			},
			expectErr: true,
		},
		{
			name: "valid IP address",
			attr: NewIPAddressAttribute(AttrNASIPAddress, [4]byte{192, 168, 1, 1}),
		},
		{
			name: "invalid IP address length",
			attr: Attribute{
				Type:   AttrNASIPAddress,
				Length: 4,
				Value:  []byte{192, 168},
			},
			expectErr: true,
		},
		{
			name: "valid Message-Authenticator",
			attr: Attribute{
				Type:   AttrMessageAuthenticator,
				Length: 18,
				Value:  make([]byte, 16),
			},
		},
		{
			name: "invalid Message-Authenticator length",
			attr: Attribute{
				Type:   AttrMessageAuthenticator,
				Length: 10,
				Value:  make([]byte, 8),
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.attr.Validate()
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAttributeString(t *testing.T) {
	attr := NewStringAttribute(AttrUserName, "testuser")
	str := attr.String()

	assert.Contains(t, str, "Type=1")
	assert.Contains(t, str, "Length=10")
	assert.Contains(t, str, "Value=8 bytes")
}

func TestAttributeCopy(t *testing.T) {
	original := NewStringAttribute(AttrUserName, "testuser")
	copied := original.Copy()

	assert.Equal(t, original.Type, copied.Type)
	assert.Equal(t, original.Length, copied.Length)
	assert.Equal(t, original.Value, copied.Value)

	// Ensure deep copy
	copied.Value[0] = 'X'
	assert.NotEqual(t, original.Value[0], copied.Value[0])
}

func TestAttributeIsVendorSpecific(t *testing.T) {
	vsaAttr := NewAttribute(AttrVendorSpecific, []byte{0x00, 0x00, 0x00, 0x09, 0x01, 0x06, 0x74, 0x65, 0x73, 0x74})
	regularAttr := NewStringAttribute(AttrUserName, "test")

	assert.True(t, vsaAttr.IsVendorSpecific())
	assert.False(t, regularAttr.IsVendorSpecific())
}

func TestAttributeGetVendorID(t *testing.T) {
	tests := []struct {
		name      string
		attr      Attribute
		expected  uint32
		expectErr bool
	}{
		{
			name:     "valid VSA",
			attr:     NewAttribute(AttrVendorSpecific, []byte{0x00, 0x00, 0x00, 0x09, 0x01, 0x06, 0x74, 0x65, 0x73, 0x74}),
			expected: 9,
		},
		{
			name:      "not VSA",
			attr:      NewStringAttribute(AttrUserName, "test"),
			expectErr: true,
		},
		{
			name:      "VSA too short",
			attr:      NewAttribute(AttrVendorSpecific, []byte{0x00, 0x00}),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.attr.GetVendorID()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestAttributeGetVendorData(t *testing.T) {
	tests := []struct {
		name      string
		attr      Attribute
		expected  []byte
		expectErr bool
	}{
		{
			name:     "valid VSA",
			attr:     NewAttribute(AttrVendorSpecific, []byte{0x00, 0x00, 0x00, 0x09, 0x01, 0x06, 0x74, 0x65, 0x73, 0x74}),
			expected: []byte{0x01, 0x06, 0x74, 0x65, 0x73, 0x74},
		},
		{
			name:      "not VSA",
			attr:      NewStringAttribute(AttrUserName, "test"),
			expectErr: true,
		},
		{
			name:      "VSA too short",
			attr:      NewAttribute(AttrVendorSpecific, []byte{0x00, 0x00}),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.attr.GetVendorData()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestNewTaggedAttribute(t *testing.T) {
	tests := []struct {
		name      string
		attrType  uint8
		tag       uint8
		value     []byte
		expectErr bool
	}{
		{
			name:     "valid tagged attribute",
			attrType: AttrTunnelType,
			tag:      0x01,
			value:    []byte{0x00, 0x00, 0x00, 0x01},
		},
		{
			name:     "valid tagged attribute with max tag",
			attrType: AttrTunnelType,
			tag:      0x1F,
			value:    []byte("test"),
		},
		{
			name:      "invalid tag value zero",
			attrType:  AttrTunnelType,
			tag:       0x00,
			value:     []byte("test"),
			expectErr: true,
		},
		{
			name:      "invalid tag value too high",
			attrType:  AttrTunnelType,
			tag:       0x20,
			value:     []byte("test"),
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, err := NewTaggedAttribute(tt.attrType, tt.tag, tt.value)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.attrType, attr.Type)
				assert.Equal(t, uint8(2+1+len(tt.value)), attr.Length)
				assert.Equal(t, tt.tag, attr.Value[0])
				assert.Equal(t, tt.value, attr.Value[1:])
			}
		})
	}
}

func TestNewTaggedStringAttribute(t *testing.T) {
	tests := []struct {
		name      string
		attrType  uint8
		tag       uint8
		value     string
		expectErr bool
	}{
		{
			name:     "valid tagged string attribute",
			attrType: AttrTunnelType,
			tag:      0x01,
			value:    "testvalue",
		},
		{
			name:      "invalid tag",
			attrType:  AttrTunnelType,
			tag:       0x00,
			value:     "testvalue",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, err := NewTaggedStringAttribute(tt.attrType, tt.tag, tt.value)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.attrType, attr.Type)
				assert.Equal(t, uint8(2+1+len(tt.value)), attr.Length)
				assert.Equal(t, tt.tag, attr.Value[0])
				assert.Equal(t, []byte(tt.value), attr.Value[1:])
			}
		})
	}
}

func TestNewTaggedIntegerAttribute(t *testing.T) {
	tests := []struct {
		name      string
		attrType  uint8
		tag       uint8
		value     uint32
		expectErr bool
	}{
		{
			name:     "valid tagged integer attribute",
			attrType: AttrTunnelType,
			tag:      0x01,
			value:    0x12345678,
		},
		{
			name:      "invalid tag",
			attrType:  AttrTunnelType,
			tag:       0x00,
			value:     0x12345678,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr, err := NewTaggedIntegerAttribute(tt.attrType, tt.tag, tt.value)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.attrType, attr.Type)
				assert.Equal(t, uint8(2+1+4), attr.Length) // 2 (header) + 1 (tag) + 4 (integer)
				assert.Equal(t, tt.tag, attr.Value[0])

				expected := []byte{
					byte(tt.value >> 24),
					byte(tt.value >> 16),
					byte(tt.value >> 8),
					byte(tt.value),
				}
				assert.Equal(t, expected, attr.Value[1:])
			}
		})
	}
}

func TestAttributeGetTaggedValue(t *testing.T) {
	tests := []struct {
		name      string
		attr      Attribute
		expectTag uint8
		expectVal []byte
		expectErr bool
	}{
		{
			name: "valid tagged attribute",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x01, 0x74, 0x65, 0x73, 0x74},
			},
			expectTag: 0x01,
			expectVal: []byte{0x74, 0x65, 0x73, 0x74},
		},
		{
			name: "valid tagged attribute with max tag",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x1F, 0x74, 0x65, 0x73, 0x74},
			},
			expectTag: 0x1F,
			expectVal: []byte{0x74, 0x65, 0x73, 0x74},
		},
		{
			name: "empty attribute",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 2,
				Value:  []byte{},
			},
			expectErr: true,
		},
		{
			name: "invalid tag value zero",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x00, 0x74, 0x65, 0x73, 0x74},
			},
			expectErr: true,
		},
		{
			name: "invalid tag value too high",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x20, 0x74, 0x65, 0x73, 0x74},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.attr.GetTaggedValue()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectTag, result.Tag)
				assert.Equal(t, tt.expectVal, result.Value)
			}
		})
	}
}

func TestAttributeGetTaggedString(t *testing.T) {
	tests := []struct {
		name      string
		attr      Attribute
		expectTag uint8
		expectVal string
		expectErr bool
	}{
		{
			name: "valid tagged string attribute",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x01, 0x74, 0x65, 0x73, 0x74},
			},
			expectTag: 0x01,
			expectVal: "test",
		},
		{
			name: "empty tagged string",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 3,
				Value:  []byte{0x01},
			},
			expectTag: 0x01,
			expectVal: "",
		},
		{
			name: "invalid tag",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x00, 0x74, 0x65, 0x73, 0x74},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, value, err := tt.attr.GetTaggedString()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectTag, tag)
				assert.Equal(t, tt.expectVal, value)
			}
		})
	}
}

func TestAttributeGetTaggedInteger(t *testing.T) {
	tests := []struct {
		name      string
		attr      Attribute
		expectTag uint8
		expectVal uint32
		expectErr bool
	}{
		{
			name: "valid tagged integer attribute",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x01, 0x12, 0x34, 0x56, 0x78},
			},
			expectTag: 0x01,
			expectVal: 0x12345678,
		},
		{
			name: "invalid tag",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 7,
				Value:  []byte{0x00, 0x12, 0x34, 0x56, 0x78},
			},
			expectErr: true,
		},
		{
			name: "invalid integer length",
			attr: Attribute{
				Type:   AttrTunnelType,
				Length: 5,
				Value:  []byte{0x01, 0x12, 0x34},
			},
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tag, value, err := tt.attr.GetTaggedInteger()

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectTag, tag)
				assert.Equal(t, tt.expectVal, value)
			}
		})
	}
}

func TestTaggedAttributeRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		attrType uint8
		tag      uint8
		value    []byte
	}{
		{
			name:     "string value",
			attrType: AttrTunnelType,
			tag:      0x01,
			value:    []byte("test-string"),
		},
		{
			name:     "integer value",
			attrType: AttrTunnelType,
			tag:      0x0F,
			value:    []byte{0x12, 0x34, 0x56, 0x78},
		},
		{
			name:     "empty value",
			attrType: AttrTunnelType,
			tag:      0x1F,
			value:    []byte{},
		},
		{
			name:     "binary value",
			attrType: AttrTunnelType,
			tag:      0x10,
			value:    []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create tagged attribute
			attr, err := NewTaggedAttribute(tt.attrType, tt.tag, tt.value)
			require.NoError(t, err)

			// Parse it back
			tagged, err := attr.GetTaggedValue()
			require.NoError(t, err)

			// Verify roundtrip
			assert.Equal(t, tt.tag, tagged.Tag)
			assert.Equal(t, tt.value, tagged.Value)
		})
	}
}

func TestTaggedAttributeWithDifferentTypes(t *testing.T) {
	// Test with different attribute types that support tags
	taggedAttrTypes := []uint8{
		AttrTunnelType,
		AttrTunnelMediumType,
		AttrTunnelClientEndpoint,
		AttrTunnelServerEndpoint,
		AttrTunnelPassword,
	}

	for _, attrType := range taggedAttrTypes {
		t.Run(fmt.Sprintf("uint8-%d", attrType), func(t *testing.T) {
			tag := uint8(0x05)
			value := []byte("test-value")

			attr, err := NewTaggedAttribute(attrType, tag, value)
			require.NoError(t, err)

			assert.Equal(t, attrType, attr.Type)
			assert.Equal(t, tag, attr.Value[0])
			assert.Equal(t, value, attr.Value[1:])

			// Test parsing back
			parsedTag, parsedValue, err := attr.GetTaggedString()
			require.NoError(t, err)
			assert.Equal(t, tag, parsedTag)
			assert.Equal(t, string(value), parsedValue)
		})
	}
}

func TestTaggedAttributeEdgeCases(t *testing.T) {
	t.Run("minimum tag value", func(t *testing.T) {
		attr, err := NewTaggedAttribute(AttrTunnelType, 0x01, []byte("test"))
		require.NoError(t, err)

		tag, value, err := attr.GetTaggedString()
		require.NoError(t, err)
		assert.Equal(t, uint8(0x01), tag)
		assert.Equal(t, "test", value)
	})

	t.Run("maximum tag value", func(t *testing.T) {
		attr, err := NewTaggedAttribute(AttrTunnelType, 0x1F, []byte("test"))
		require.NoError(t, err)

		tag, value, err := attr.GetTaggedString()
		require.NoError(t, err)
		assert.Equal(t, uint8(0x1F), tag)
		assert.Equal(t, "test", value)
	})

	t.Run("large value", func(t *testing.T) {
		largeValue := make([]byte, 250) // Close to max attribute length
		for i := range largeValue {
			largeValue[i] = byte(i % 256)
		}

		attr, err := NewTaggedAttribute(AttrTunnelType, 0x10, largeValue)
		require.NoError(t, err)

		tagged, err := attr.GetTaggedValue()
		require.NoError(t, err)
		assert.Equal(t, uint8(0x10), tagged.Tag)
		assert.Equal(t, largeValue, tagged.Value)
	})
}

func TestTaggedAttributeErrors(t *testing.T) {
	t.Run("tag boundary violations", func(t *testing.T) {
		invalidTags := []uint8{0x00, 0x20, 0x30, 0xFF}

		for _, tag := range invalidTags {
			_, err := NewTaggedAttribute(AttrTunnelType, tag, []byte("test"))
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid tag value")
		}
	})

	t.Run("malformed tagged value parsing", func(t *testing.T) {
		malformedAttrs := []Attribute{
			{
				Type:   AttrTunnelType,
				Length: 2,
				Value:  []byte{}, // Empty value
			},
			{
				Type:   AttrTunnelType,
				Length: 3,
				Value:  []byte{0x00}, // Invalid tag 0x00
			},
			{
				Type:   AttrTunnelType,
				Length: 3,
				Value:  []byte{0x20}, // Invalid tag 0x20
			},
		}

		for i, attr := range malformedAttrs {
			t.Run(fmt.Sprintf("malformed-%d", i), func(t *testing.T) {
				_, err := attr.GetTaggedValue()
				assert.Error(t, err)
			})
		}
	})
}
