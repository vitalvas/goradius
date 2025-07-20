package packet

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/dictionary"
)

func TestNewEnhancedPacket(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 123, dict)

	assert.NotNil(t, pkt)
	assert.Equal(t, CodeAccessRequest, pkt.Code)
	assert.Equal(t, uint8(123), pkt.Identifier)
	assert.NotNil(t, pkt.parser)
}

func TestWrapPacket(t *testing.T) {
	dict := createTestDictionary()
	basePkt := New(CodeAccessAccept, 200)
	basePkt.AddAttribute(NewStringAttribute(AttrUserName, "test"))

	pkt := WrapPacket(basePkt, dict)

	assert.NotNil(t, pkt)
	assert.Equal(t, CodeAccessAccept, pkt.Code)
	assert.Equal(t, uint8(200), pkt.Identifier)
	assert.Len(t, pkt.Attributes, 1)
}

func TestEnhancedPacket_AddTypedAttribute(t *testing.T) {
	dict := createTestDictionary()

	t.Run("string attribute", func(t *testing.T) {
		pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)
		err := pkt.AddTypedAttribute(AttrUserName, "testuser")
		require.NoError(t, err)

		// Verify it was added
		attr, found := pkt.GetAttribute(AttrUserName)
		assert.True(t, found)
		assert.Equal(t, "testuser", string(attr.Value))
	})

	t.Run("integer attribute", func(t *testing.T) {
		pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)
		err := pkt.AddTypedAttribute(AttrServiceType, uint32(2))
		require.NoError(t, err)

		// Verify it was added with correct binary encoding
		attr, found := pkt.GetAttribute(AttrServiceType)
		assert.True(t, found)
		expected := []byte{0, 0, 0, 2}
		assert.Equal(t, expected, attr.Value)
	})

	t.Run("named value attribute", func(t *testing.T) {
		pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)
		err := pkt.AddTypedAttribute(AttrServiceType, "Login-User")
		require.NoError(t, err)

		// Should encode to value 1
		attr, found := pkt.GetAttribute(AttrServiceType)
		assert.True(t, found)
		expected := []byte{0, 0, 0, 1}
		assert.Equal(t, expected, attr.Value)
	})

	t.Run("IP address attribute", func(t *testing.T) {
		pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)
		ip := net.ParseIP("192.168.1.1")
		err := pkt.AddTypedAttribute(AttrNASIPAddress, ip)
		require.NoError(t, err)

		attr, found := pkt.GetAttribute(AttrNASIPAddress)
		assert.True(t, found)
		expected := []byte{192, 168, 1, 1}
		assert.Equal(t, expected, attr.Value)
	})

	t.Run("invalid attribute", func(t *testing.T) {
		pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)
		err := pkt.AddTypedAttribute(AttrServiceType, "invalid-value")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unknown named value")
	})
}

func TestEnhancedPacket_AddVSA(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	t.Run("known VSA", func(t *testing.T) {
		err := pkt.AddVSA(9, 1, uint32(42))
		require.NoError(t, err)

		// Verify VSA was added
		attrs := pkt.GetAttributes(AttrVendorSpecific)
		assert.Len(t, attrs, 1)

		attr := attrs[0]
		assert.Equal(t, AttrVendorSpecific, attr.Type)

		// Check VSA structure
		expected := []byte{
			0, 0, 0, 9, // Vendor ID
			1,           // Vendor Type
			6,           // Vendor Length
			0, 0, 0, 42, // Value
		}
		assert.Equal(t, expected, attr.Value)
	})

	t.Run("unknown VSA with raw bytes", func(t *testing.T) {
		data := []byte{1, 2, 3}
		err := pkt.AddVSA(999, 1, data)
		require.NoError(t, err)

		attrs := pkt.GetAttributes(AttrVendorSpecific)
		assert.Len(t, attrs, 2) // Previous test + this one
	})
}

func TestEnhancedPacket_GetTypedAttribute(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	// Add some attributes
	pkt.AddTypedAttribute(AttrUserName, "testuser")
	pkt.AddTypedAttribute(AttrServiceType, "Framed-User")
	pkt.AddTypedAttribute(AttrNASIPAddress, net.ParseIP("10.0.0.1"))

	t.Run("string attribute", func(t *testing.T) {
		value, found, err := pkt.GetTypedAttribute(AttrUserName)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "testuser", value)
	})

	t.Run("named value attribute", func(t *testing.T) {
		value, found, err := pkt.GetTypedAttribute(AttrServiceType)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, "Framed-User", value)
	})

	t.Run("IP address attribute", func(t *testing.T) {
		value, found, err := pkt.GetTypedAttribute(AttrNASIPAddress)
		require.NoError(t, err)
		assert.True(t, found)
		ip, ok := value.(net.IP)
		require.True(t, ok)
		assert.True(t, net.ParseIP("10.0.0.1").Equal(ip))
	})

	t.Run("non-existent attribute", func(t *testing.T) {
		value, found, err := pkt.GetTypedAttribute(AttrState)
		require.NoError(t, err)
		assert.False(t, found)
		assert.Nil(t, value)
	})
}

func TestEnhancedPacket_GetVSA(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	// Add some VSAs
	pkt.AddVSA(9, 1, uint32(42))
	pkt.AddVSA(9, 2, []byte{1, 2, 3}) // Unknown VSA type

	t.Run("known VSA", func(t *testing.T) {
		value, found, err := pkt.GetVSA(9, 1)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, uint32(42), value)
	})

	t.Run("unknown VSA type", func(t *testing.T) {
		value, found, err := pkt.GetVSA(9, 2)
		require.NoError(t, err)
		assert.True(t, found)
		// Should return raw bytes since no dictionary definition
		expected := []byte{1, 2, 3}
		assert.Equal(t, expected, value)
	})

	t.Run("non-existent VSA", func(t *testing.T) {
		value, found, err := pkt.GetVSA(999, 1)
		require.NoError(t, err)
		assert.False(t, found)
		assert.Nil(t, value)
	})
}

func TestEnhancedPacket_GetVSAs(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	// Add multiple VSAs for Cisco (vendor ID 9)
	pkt.AddVSA(9, 1, uint32(42))
	pkt.AddVSA(9, 2, []byte{1, 2, 3})
	pkt.AddVSA(999, 1, []byte{4, 5, 6}) // Different vendor

	vsas, err := pkt.GetVSAs(9)
	require.NoError(t, err)
	assert.Len(t, vsas, 2)

	assert.Equal(t, uint32(42), vsas[1])
	assert.Equal(t, []byte{1, 2, 3}, vsas[2])
}

func TestEnhancedPacket_ArrayAttributes(t *testing.T) {
	dict := createTestDictionary()

	// Add array attribute to dictionary
	dict.AddAttribute(&dictionary.AttributeDefinition{
		Name:     "Test-Array",
		ID:       99,
		DataType: dictionary.DataTypeString,
		Array:    true,
	})

	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	t.Run("add array attribute", func(t *testing.T) {
		values := []interface{}{"value1", "value2", "value3"}
		err := pkt.AddArrayAttribute(uint8(99), values)
		require.NoError(t, err)

		// Should have 3 attributes of the same type
		attrs := pkt.GetAttributes(uint8(99))
		assert.Len(t, attrs, 3)
	})

	t.Run("get array attribute", func(t *testing.T) {
		arrayAttr, err := pkt.GetArrayAttribute(uint8(99))
		require.NoError(t, err)
		require.NotNil(t, arrayAttr)

		assert.Equal(t, uint8(99), arrayAttr.Type)
		assert.Len(t, arrayAttr.Values, 3)
		assert.Equal(t, "value1", arrayAttr.Values[0])
		assert.Equal(t, "value2", arrayAttr.Values[1])
		assert.Equal(t, "value3", arrayAttr.Values[2])
	})

	t.Run("is array attribute", func(t *testing.T) {
		assert.True(t, pkt.IsArrayAttribute(uint8(99)))
		assert.False(t, pkt.IsArrayAttribute(AttrUserName))
	})

	t.Run("get typed attributes", func(t *testing.T) {
		values, err := pkt.GetTypedAttributes(uint8(99))
		require.NoError(t, err)
		assert.Len(t, values, 3)
		assert.Equal(t, "value1", values[0])
		assert.Equal(t, "value2", values[1])
		assert.Equal(t, "value3", values[2])
	})
}

func TestEnhancedPacket_ConvenienceMethods(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	t.Run("user name", func(t *testing.T) {
		err := pkt.SetUserName("testuser")
		require.NoError(t, err)

		username, found := pkt.GetUserName()
		assert.True(t, found)
		assert.Equal(t, "testuser", username)
	})

	t.Run("NAS IP address", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.1")
		err := pkt.SetNASIPAddress(ip)
		require.NoError(t, err)

		retrievedIP, found := pkt.GetNASIPAddress()
		assert.True(t, found)
		assert.True(t, ip.Equal(retrievedIP))
	})

	t.Run("service type with named value", func(t *testing.T) {
		err := pkt.SetServiceType("Login-User")
		require.NoError(t, err)

		serviceType, found := pkt.GetServiceType()
		assert.True(t, found)
		assert.Equal(t, "Login-User", serviceType)
	})

	t.Run("service type with numeric value", func(t *testing.T) {
		pkt2 := NewEnhancedPacket(CodeAccessRequest, 2, dict)
		err := pkt2.SetServiceType(uint32(2))
		require.NoError(t, err)

		serviceType, found := pkt2.GetServiceType()
		assert.True(t, found)
		assert.Equal(t, "Framed-User", serviceType) // Should map to named value
	})
}

func TestEnhancedPacket_ValidatePacket(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	t.Run("valid packet", func(t *testing.T) {
		pkt.AddTypedAttribute(AttrUserName, "testuser")
		pkt.AddTypedAttribute(AttrServiceType, "Login-User")

		err := pkt.ValidatePacket()
		assert.NoError(t, err)
	})

	t.Run("invalid attribute length", func(t *testing.T) {
		// Add fixed-length attribute with wrong length (use our test "Challenge" attribute)
		pkt.AddAttribute(NewAttribute(uint8(60), []byte{1, 2, 3})) // Should be 10 bytes

		err := pkt.ValidatePacket()
		assert.Error(t, err)
		// This will fail basic validation first, but we still get an error
		assert.Contains(t, err.Error(), "length mismatch")
	})
}

func TestEnhancedPacket_String(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 123, dict)

	pkt.AddTypedAttribute(AttrUserName, "testuser")
	pkt.AddTypedAttribute(AttrServiceType, "Login-User")
	pkt.AddTypedAttribute(AttrNASIPAddress, net.ParseIP("10.0.0.1"))

	str := pkt.String()

	assert.Contains(t, str, "RADIUS Access-Request")
	assert.Contains(t, str, "ID: 123")
	assert.Contains(t, str, "User-Name")
	assert.Contains(t, str, "testuser")
	assert.Contains(t, str, "Service-Type")
	assert.Contains(t, str, "Login-User")
	assert.Contains(t, str, "NAS-IP-Address")
	assert.Contains(t, str, "10.0.0.1")
}

func TestEnhancedPacket_GetAttributeName(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	t.Run("known attribute", func(t *testing.T) {
		name := pkt.GetAttributeName(AttrUserName)
		assert.Equal(t, "User-Name", name)
	})

	t.Run("unknown attribute", func(t *testing.T) {
		name := pkt.GetAttributeName(uint8(250))
		assert.Equal(t, "Attr-250", name)
	})
}

func TestEnhancedPacket_GetVSAName(t *testing.T) {
	dict := createTestDictionary()
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, dict)

	t.Run("known VSA", func(t *testing.T) {
		name := pkt.GetVSAName(9, 1)
		assert.Equal(t, "Cisco-AVPair", name)
	})

	t.Run("known vendor, unknown attribute", func(t *testing.T) {
		name := pkt.GetVSAName(9, 99)
		assert.Equal(t, "Cisco-Attr-99", name)
	})

	t.Run("unknown vendor", func(t *testing.T) {
		name := pkt.GetVSAName(999, 1)
		assert.Equal(t, "VSA-999:1", name)
	})
}

func TestEnhancedPacket_WithoutDictionary(t *testing.T) {
	// Test behavior without dictionary
	pkt := NewEnhancedPacket(CodeAccessRequest, 1, nil)

	t.Run("add raw attribute", func(t *testing.T) {
		data := []byte("test")
		err := pkt.AddTypedAttribute(AttrUserName, data)
		require.NoError(t, err)

		attr, found := pkt.GetAttribute(AttrUserName)
		assert.True(t, found)
		assert.Equal(t, data, attr.Value)
	})

	t.Run("get raw attribute", func(t *testing.T) {
		value, found, err := pkt.GetTypedAttribute(AttrUserName)
		require.NoError(t, err)
		assert.True(t, found)
		assert.Equal(t, []byte("test"), value)
	})

	t.Run("attribute names", func(t *testing.T) {
		name := pkt.GetAttributeName(AttrUserName)
		assert.Equal(t, "Attr-1", name)
	})

	t.Run("array attribute check", func(t *testing.T) {
		isArray := pkt.IsArrayAttribute(AttrUserName)
		assert.False(t, isArray)
	})
}
