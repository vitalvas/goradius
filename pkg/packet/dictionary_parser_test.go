package packet

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
)

func TestNewDictionaryParser(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	assert.NotNil(t, parser)
	assert.Equal(t, dict, parser.dict)
}

func TestDictionaryParser_ParseAttributeValue(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("string attribute", func(t *testing.T) {
		attr := NewStringAttribute(AttrUserName, "testuser")
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.Equal(t, "testuser", value)
	})

	t.Run("integer attribute", func(t *testing.T) {
		attr := NewIntegerAttribute(AttrServiceType, 2)
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.Equal(t, "Framed-User", value) // Value 2 maps to "Framed-User"
	})

	t.Run("integer attribute with named value", func(t *testing.T) {
		attr := NewIntegerAttribute(AttrServiceType, 1) // Login-User
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.Equal(t, "Login-User", value)
	})

	t.Run("IP address attribute", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.1")
		attr := NewIPAddressAttribute(AttrNASIPAddress, [4]byte{192, 168, 1, 1})
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.True(t, ip.Equal(value.(net.IP)))
	})

	t.Run("octets attribute", func(t *testing.T) {
		data := []byte{1, 2, 3, 4}
		attr := NewAttribute(AttrState, data)
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.Equal(t, data, value)
	})

	t.Run("VSA attribute", func(t *testing.T) {
		// Build VSA manually
		vsaValue := make([]byte, 10)
		// Vendor ID (9 = Cisco)
		vsaValue[0] = 0
		vsaValue[1] = 0
		vsaValue[2] = 0
		vsaValue[3] = 9
		// Vendor Type (1)
		vsaValue[4] = 1
		// Vendor Length (6 = 2 header + 4 value bytes)
		vsaValue[5] = 6
		// Value (4 bytes for integer)
		vsaValue[6] = 0
		vsaValue[7] = 0
		vsaValue[8] = 0
		vsaValue[9] = 42

		attr := NewAttribute(AttrVendorSpecific, vsaValue)
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.Equal(t, uint32(42), value)
	})

	t.Run("unknown attribute", func(t *testing.T) {
		attr := NewAttribute(uint8(200), []byte{1, 2, 3})
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.Equal(t, []byte{1, 2, 3}, value)
	})

	t.Run("without dictionary", func(t *testing.T) {
		parser := NewDictionaryParser(nil)
		attr := NewStringAttribute(AttrUserName, "test")
		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)
		assert.Equal(t, attr.Value, value)
	})
}

func TestDictionaryParser_BuildAttributeValue(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("string value", func(t *testing.T) {
		value, err := parser.BuildAttributeValue(AttrUserName, "testuser")
		require.NoError(t, err)
		assert.Equal(t, []byte("testuser"), value)
	})

	t.Run("integer value", func(t *testing.T) {
		value, err := parser.BuildAttributeValue(AttrServiceType, uint32(2))
		require.NoError(t, err)
		expected := []byte{0, 0, 0, 2}
		assert.Equal(t, expected, value)
	})

	t.Run("integer named value", func(t *testing.T) {
		value, err := parser.BuildAttributeValue(AttrServiceType, "Login-User")
		require.NoError(t, err)
		expected := []byte{0, 0, 0, 1}
		assert.Equal(t, expected, value)
	})

	t.Run("IP address value", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.1")
		value, err := parser.BuildAttributeValue(AttrNASIPAddress, ip)
		require.NoError(t, err)
		expected := []byte{192, 168, 1, 1}
		assert.Equal(t, expected, value)
	})

	t.Run("IP address string value", func(t *testing.T) {
		value, err := parser.BuildAttributeValue(AttrNASIPAddress, "10.0.0.1")
		require.NoError(t, err)
		expected := []byte{10, 0, 0, 1}
		assert.Equal(t, expected, value)
	})

	t.Run("date value", func(t *testing.T) {
		timestamp := time.Unix(1234567890, 0)
		value, err := parser.BuildAttributeValue(uint8(55), timestamp)
		require.NoError(t, err)
		// 1234567890 = 0x499602D2
		expected := []byte{0x49, 0x96, 0x02, 0xD2}
		assert.Equal(t, expected, value)
	})

	t.Run("fixed length string", func(t *testing.T) {
		value, err := parser.BuildAttributeValue(uint8(60), "test")
		require.NoError(t, err)
		expected := []byte{'t', 'e', 's', 't', 0, 0, 0, 0, 0, 0}
		assert.Equal(t, expected, value)
	})

	t.Run("unknown attribute with raw bytes", func(t *testing.T) {
		data := []byte{1, 2, 3}
		value, err := parser.BuildAttributeValue(uint8(200), data)
		require.NoError(t, err)
		assert.Equal(t, data, value)
	})

	t.Run("without dictionary", func(t *testing.T) {
		parser := NewDictionaryParser(nil)
		data := []byte{1, 2, 3}
		value, err := parser.BuildAttributeValue(AttrUserName, data)
		require.NoError(t, err)
		assert.Equal(t, data, value)
	})
}

func TestDictionaryParser_BuildVSAValue(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("known VSA", func(t *testing.T) {
		value, err := parser.BuildVSAValue(9, 1, uint32(42))
		require.NoError(t, err)

		expected := []byte{
			0, 0, 0, 9, // Vendor ID (Cisco)
			1,           // Vendor Type
			6,           // Vendor Length (2 + 4)
			0, 0, 0, 42, // Value (4 bytes for integer)
		}
		assert.Equal(t, expected, value)
	})

	t.Run("unknown VSA with raw bytes", func(t *testing.T) {
		data := []byte{1, 2, 3}
		value, err := parser.BuildVSAValue(999, 1, data)
		require.NoError(t, err)

		expected := []byte{
			0, 0, 3, 231, // Vendor ID (999)
			1,       // Vendor Type
			5,       // Vendor Length (2 + 3)
			1, 2, 3, // Value
		}
		assert.Equal(t, expected, value)
	})

	t.Run("without dictionary", func(t *testing.T) {
		parser := NewDictionaryParser(nil)
		_, err := parser.BuildVSAValue(9, 1, uint32(42))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dictionary required")
	})
}

func TestDictionaryParser_GetAttributeName(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("known attribute", func(t *testing.T) {
		name := parser.GetAttributeName(AttrUserName)
		assert.Equal(t, "User-Name", name)
	})

	t.Run("unknown attribute", func(t *testing.T) {
		name := parser.GetAttributeName(uint8(200))
		assert.Equal(t, "Attr-200", name)
	})

	t.Run("without dictionary", func(t *testing.T) {
		parser := NewDictionaryParser(nil)
		name := parser.GetAttributeName(AttrUserName)
		assert.Equal(t, "Attr-1", name)
	})
}

func TestDictionaryParser_GetVSAName(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("known VSA", func(t *testing.T) {
		name := parser.GetVSAName(9, 1)
		assert.Equal(t, "Cisco-AVPair", name)
	})

	t.Run("known vendor, unknown attribute", func(t *testing.T) {
		name := parser.GetVSAName(9, 99)
		assert.Equal(t, "Cisco-Attr-99", name)
	})

	t.Run("unknown vendor and attribute", func(t *testing.T) {
		name := parser.GetVSAName(999, 1)
		assert.Equal(t, "VSA-999:1", name)
	})

	t.Run("without dictionary", func(t *testing.T) {
		parser := NewDictionaryParser(nil)
		name := parser.GetVSAName(9, 1)
		assert.Equal(t, "VSA-9:1", name)
	})
}

func TestDictionaryParser_ValidateAttribute(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("valid attribute", func(t *testing.T) {
		attr := NewStringAttribute(AttrUserName, "test")
		err := parser.ValidateAttribute(attr)
		assert.NoError(t, err)
	})

	t.Run("fixed length attribute - correct length", func(t *testing.T) {
		attr := NewAttribute(uint8(60), make([]byte, 10)) // Fixed length 10
		err := parser.ValidateAttribute(attr)
		assert.NoError(t, err)
	})

	t.Run("fixed length attribute - wrong length", func(t *testing.T) {
		attr := NewAttribute(uint8(60), make([]byte, 5)) // Should be 10
		err := parser.ValidateAttribute(attr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "length mismatch")
	})

	t.Run("unknown attribute", func(t *testing.T) {
		attr := NewAttribute(uint8(200), []byte{1, 2, 3})
		err := parser.ValidateAttribute(attr)
		assert.NoError(t, err) // Unknown attributes are allowed
	})

	t.Run("VSA validation", func(t *testing.T) {
		vsaValue := make([]byte, 10)
		// Vendor ID (9 = Cisco)
		vsaValue[0] = 0
		vsaValue[1] = 0
		vsaValue[2] = 0
		vsaValue[3] = 9
		// Vendor Type (1)
		vsaValue[4] = 1
		// Vendor Length (4)
		vsaValue[5] = 4
		// Value (2 bytes)
		vsaValue[6] = 0
		vsaValue[7] = 42

		attr := NewAttribute(AttrVendorSpecific, vsaValue[:8]) // Correct length
		err := parser.ValidateAttribute(attr)
		assert.NoError(t, err)
	})

	t.Run("invalid VSA header", func(t *testing.T) {
		attr := NewAttribute(AttrVendorSpecific, []byte{1, 2}) // Too short
		err := parser.ValidateAttribute(attr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "VSA value too short")
	})

	t.Run("without dictionary", func(t *testing.T) {
		parser := NewDictionaryParser(nil)
		attr := NewStringAttribute(AttrUserName, "test")
		err := parser.ValidateAttribute(attr)
		assert.NoError(t, err)
	})
}

func TestDictionaryParser_DataTypeHandling(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("uint64 encoding and parsing", func(t *testing.T) {
		value := uint64(0x123456789ABCDEF0)

		// Build value
		encoded, err := parser.encodeValueByType(value, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeUint64,
		})
		require.NoError(t, err)

		expected := []byte{0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0}
		assert.Equal(t, expected, encoded)

		// Parse value back
		parsed, err := parser.parseValueByType(encoded, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeUint64,
		})
		require.NoError(t, err)
		assert.Equal(t, value, parsed)
	})

	t.Run("IPv6 address handling", func(t *testing.T) {
		ip := net.ParseIP("2001:db8::1")

		// Build value
		encoded, err := parser.encodeValueByType(ip, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeIPv6Addr,
		})
		require.NoError(t, err)
		assert.Len(t, encoded, 16)

		// Parse value back
		parsed, err := parser.parseValueByType(encoded, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeIPv6Addr,
		})
		require.NoError(t, err)
		assert.True(t, ip.Equal(parsed.(net.IP)))
	})

	t.Run("date handling", func(t *testing.T) {
		timestamp := time.Unix(1234567890, 0)

		// Build value
		encoded, err := parser.encodeValueByType(timestamp, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeDate,
		})
		require.NoError(t, err)
		assert.Len(t, encoded, 4)

		// Parse value back
		parsed, err := parser.parseValueByType(encoded, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeDate,
		})
		require.NoError(t, err)
		assert.Equal(t, timestamp.Unix(), parsed.(time.Time).Unix())
	})
}

func TestDictionaryParser_ErrorHandling(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("invalid integer length", func(t *testing.T) {
		_, err := parser.parseValueByType([]byte{1, 2, 3}, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeInteger,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 4 bytes")
	})

	t.Run("invalid IP address length", func(t *testing.T) {
		_, err := parser.parseValueByType([]byte{1, 2, 3}, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeIPAddr,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be 4 bytes")
	})

	t.Run("invalid string encoding for integer", func(t *testing.T) {
		_, err := parser.encodeValueByType("not-a-number", &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeInteger,
			Values:   map[string]uint32{"test": 1},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown named value")
	})

	t.Run("negative value for uint32", func(t *testing.T) {
		_, err := parser.encodeValueByType(-1, &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeUint32,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "negative value not allowed")
	})

	t.Run("invalid IP address string", func(t *testing.T) {
		_, err := parser.encodeValueByType("not-an-ip", &dictionary.AttributeDefinition{
			DataType: dictionary.DataTypeIPAddr,
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP address")
	})

	t.Run("fixed length string too long", func(t *testing.T) {
		_, err := parser.encodeValueByType("this-is-too-long", &dictionary.AttributeDefinition{
			DataType: "string[10]",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "too long")
	})
}

func TestDictionaryParser_TaggedAttributes(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("parse tagged string attribute", func(t *testing.T) {
		// Create a tagged attribute manually
		attr := Attribute{
			Type:   AttrTunnelType,
			Length: 8,
			Value:  []byte{0x01, 't', 'e', 's', 't'},
		}

		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)

		tagged, ok := value.(*TaggedValue)
		require.True(t, ok)
		assert.Equal(t, uint8(0x01), tagged.Tag)
		assert.Equal(t, []byte("test"), tagged.Value)
	})

	t.Run("parse tagged integer attribute", func(t *testing.T) {
		// Create a tagged integer attribute manually
		attr := Attribute{
			Type:   AttrTunnelType,
			Length: 8,
			Value:  []byte{0x05, 0x00, 0x00, 0x00, 0x42},
		}

		value, err := parser.ParseAttributeValue(attr)
		require.NoError(t, err)

		tagged, ok := value.(*TaggedValue)
		require.True(t, ok)
		assert.Equal(t, uint8(0x05), tagged.Tag)
		assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x42}, tagged.Value)
	})

	t.Run("build tagged attribute value", func(t *testing.T) {
		tagged := &TaggedValue{
			Tag:   0x01,
			Value: []byte("test"),
		}

		value, err := parser.BuildAttributeValue(AttrTunnelType, tagged)
		require.NoError(t, err)

		expected := []byte{0x01, 't', 'e', 's', 't'}
		assert.Equal(t, expected, value)
	})

	t.Run("build tagged attribute value with invalid tag", func(t *testing.T) {
		tagged := &TaggedValue{
			Tag:   0x00, // Invalid tag
			Value: []byte("test"),
		}

		_, err := parser.BuildAttributeValue(AttrTunnelType, tagged)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tag value")
	})

	t.Run("build tagged attribute for non-tagged type", func(t *testing.T) {
		tagged := &TaggedValue{
			Tag:   0x01,
			Value: []byte("test"),
		}

		_, err := parser.BuildAttributeValue(AttrUserName, tagged)
		assert.Error(t, err)
		// The error message will vary depending on the data type
		assert.Error(t, err)
	})
}

func TestDictionaryParser_BuildTaggedAttributeValue(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("build tagged string attribute", func(t *testing.T) {
		value, err := parser.BuildTaggedAttributeValue(uint8(200), 0x01, "test")
		require.NoError(t, err)

		expected := []byte{0x01, 't', 'e', 's', 't'}
		assert.Equal(t, expected, value)
	})

	t.Run("build tagged integer attribute", func(t *testing.T) {
		value, err := parser.BuildTaggedAttributeValue(AttrTunnelType, 0x05, uint32(0x12345678))
		require.NoError(t, err)

		expected := []byte{0x05, 0x12, 0x34, 0x56, 0x78}
		assert.Equal(t, expected, value)
	})

	t.Run("build tagged attribute with invalid tag", func(t *testing.T) {
		_, err := parser.BuildTaggedAttributeValue(AttrTunnelType, 0x00, "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid tag value")
	})

	t.Run("build tagged attribute with max tag", func(t *testing.T) {
		value, err := parser.BuildTaggedAttributeValue(uint8(200), 0x1F, "test")
		require.NoError(t, err)

		expected := []byte{0x1F, 't', 'e', 's', 't'}
		assert.Equal(t, expected, value)
	})

	t.Run("build tagged attribute for unknown type", func(t *testing.T) {
		_, err := parser.BuildTaggedAttributeValue(uint8(99), 0x01, "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown attribute type")
	})

	t.Run("build tagged attribute for non-tagged type", func(t *testing.T) {
		_, err := parser.BuildTaggedAttributeValue(AttrUserName, 0x01, "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not tagged")
	})

	t.Run("without dictionary", func(t *testing.T) {
		parser := NewDictionaryParser(nil)
		_, err := parser.BuildTaggedAttributeValue(AttrTunnelType, 0x01, "test")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "dictionary required")
	})
}

func TestDictionaryParser_TaggedAttributeValidation(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("validate tagged attribute with valid tag", func(t *testing.T) {
		attr := Attribute{
			Type:   AttrTunnelType,
			Length: 8,
			Value:  []byte{0x01, 't', 'e', 's', 't'},
		}

		err := parser.ValidateAttribute(attr)
		assert.NoError(t, err)
	})

	t.Run("validate tagged attribute with invalid tag", func(t *testing.T) {
		attr := Attribute{
			Type:   AttrTunnelType,
			Length: 8,
			Value:  []byte{0x00, 't', 'e', 's', 't'}, // Invalid tag 0x00
		}

		value, err := parser.ParseAttributeValue(attr)
		assert.Error(t, err)
		assert.Nil(t, value)
		assert.Contains(t, err.Error(), "invalid tag value")
	})

	t.Run("validate tagged attribute with empty value", func(t *testing.T) {
		attr := Attribute{
			Type:   AttrTunnelType,
			Length: 2,
			Value:  []byte{}, // Empty value
		}

		value, err := parser.ParseAttributeValue(attr)
		assert.Error(t, err)
		assert.Nil(t, value)
		assert.Contains(t, err.Error(), "tagged attribute cannot be empty")
	})
}

func TestDictionaryParser_TaggedAttributeRoundTrip(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	tests := []struct {
		name     string
		attrType uint8
		tag      uint8
		value    interface{}
	}{
		{
			name:     "string value",
			attrType: uint8(200), // Tagged-Test-String
			tag:      0x01,
			value:    "test-string",
		},
		{
			name:     "integer value",
			attrType: AttrTunnelType, // Tunnel-Type (integer)
			tag:      0x10,
			value:    uint32(12345),
		},
		{
			name:     "empty string",
			attrType: uint8(200), // Tagged-Test-String
			tag:      0x1F,
			value:    "",
		},
		{
			name:     "binary data as string",
			attrType: uint8(200), // Tagged-Test-String
			tag:      0x05,
			value:    string([]byte{0x01, 0x02, 0x03, 0xFF}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build tagged attribute
			built, err := parser.BuildTaggedAttributeValue(tt.attrType, tt.tag, tt.value)
			require.NoError(t, err)

			// Create attribute with built value
			attr := Attribute{
				Type:   tt.attrType,
				Length: uint8(2 + len(built)),
				Value:  built,
			}

			// Parse it back
			parsed, err := parser.ParseAttributeValue(attr)
			require.NoError(t, err)

			// Verify it's a TaggedValue
			tagged, ok := parsed.(*TaggedValue)
			require.True(t, ok)
			assert.Equal(t, tt.tag, tagged.Tag)

			// Verify the value based on type
			switch v := tt.value.(type) {
			case string:
				assert.Equal(t, []byte(v), tagged.Value)
			case uint32:
				expected := []byte{
					byte(v >> 24),
					byte(v >> 16),
					byte(v >> 8),
					byte(v),
				}
				assert.Equal(t, expected, tagged.Value)
			}
		})
	}
}

func TestDictionaryParser_TaggedAttributeErrorCases(t *testing.T) {
	dict := createTestDictionary()
	parser := NewDictionaryParser(dict)

	t.Run("tag value boundary errors", func(t *testing.T) {
		invalidTags := []uint8{0x00, 0x20, 0x30, 0xFF}

		for _, tag := range invalidTags {
			_, err := parser.BuildTaggedAttributeValue(uint8(200), tag, "test")
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid tag value")
		}
	})

	t.Run("parse malformed tagged attributes", func(t *testing.T) {
		malformedAttrs := []struct {
			name string
			attr Attribute
		}{
			{
				name: "empty value",
				attr: Attribute{
					Type:   AttrTunnelType,
					Length: 2,
					Value:  []byte{},
				},
			},
			{
				name: "invalid tag 0x00",
				attr: Attribute{
					Type:   AttrTunnelType,
					Length: 6,
					Value:  []byte{0x00, 't', 'e', 's', 't'},
				},
			},
			{
				name: "invalid tag 0x20",
				attr: Attribute{
					Type:   AttrTunnelType,
					Length: 6,
					Value:  []byte{0x20, 't', 'e', 's', 't'},
				},
			},
		}

		for _, test := range malformedAttrs {
			t.Run(test.name, func(t *testing.T) {
				_, err := parser.ParseAttributeValue(test.attr)
				assert.Error(t, err)
			})
		}
	})

	t.Run("unsupported value type for tagged attribute", func(t *testing.T) {
		// Try to build a tagged attribute with a complex struct
		type complexStruct struct {
			Field string
		}

		_, err := parser.BuildTaggedAttributeValue(uint8(200), 0x01, complexStruct{Field: "test"})
		assert.Error(t, err)
	})
}

// createTestDictionary creates a test dictionary for testing
func createTestDictionary() *dictionary.Dictionary {
	// Start with the standard dictionary which has all standard attributes
	dict := dictionaries.NewStandardDictionary()

	// Add vendors for testing
	dict.AddVendor(&dictionary.VendorDefinition{
		Name: "Cisco",
		ID:   9,
	})

	// Add a fixed-length string attribute for testing (not in RFC)
	dict.AddAttribute(&dictionary.AttributeDefinition{
		Name:     "Challenge",
		ID:       60,
		DataType: dictionary.DataTypeString,
		Length:   10,
	})

	// Add a tagged string attribute for testing (not in RFC)
	dict.AddAttribute(&dictionary.AttributeDefinition{
		Name:     "Tagged-Test-String",
		ID:       200,
		DataType: dictionary.DataTypeString,
		HasTag:   true,
	})

	// Add VSA for testing
	dict.AddAttribute(&dictionary.AttributeDefinition{
		Name:     "Cisco-AVPair",
		ID:       1,
		DataType: dictionary.DataTypeInteger,
		VendorID: 9,
	})

	return dict
}
