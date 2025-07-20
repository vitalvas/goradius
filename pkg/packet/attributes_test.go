package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vitalvas/goradius/pkg/dictionaries"
)

func TestDictionaryBasedAttributes(t *testing.T) {
	// Test that attributes are using dictionary values, not hardcoded ones
	assert.Equal(t, uint8(1), AttrUserName)
	assert.Equal(t, uint8(2), AttrUserPassword)
	assert.Equal(t, uint8(4), AttrNASIPAddress)
	assert.Equal(t, uint8(5), AttrNASPort)
	assert.Equal(t, uint8(6), AttrServiceType)
	assert.Equal(t, uint8(26), AttrVendorSpecific)

	// Test accounting attributes
	assert.Equal(t, uint8(40), AttrAcctStatusType)
	assert.Equal(t, uint8(44), AttrAcctSessionID)

	// Test extension attributes
	assert.Equal(t, uint8(60), AttrCHAPChallenge)
	assert.Equal(t, uint8(64), AttrTunnelType)
	assert.Equal(t, uint8(80), AttrMessageAuthenticator)
}

func TestAttributeTypes(t *testing.T) {
	dict := dictionaries.NewStandardDictionary()
	at := NewAttributeTypes(dict)

	// Test GetType method
	userNameType, err := at.GetType("User-Name")
	assert.NoError(t, err)
	assert.Equal(t, uint8(1), userNameType)

	// Test GetName method
	name := at.GetName(1)
	assert.Equal(t, "User-Name", name)

	// Test non-existent attribute
	_, err = at.GetType("Non-Existent-Attribute")
	assert.Error(t, err)

	// Test unknown attribute type
	name = at.GetName(200)
	assert.Equal(t, "Attr-200", name)
}

func TestGetDefaultDictionary(t *testing.T) {
	dict := GetDefaultDictionary()
	assert.NotNil(t, dict)

	// Test that subsequent calls return the same instance
	dict2 := GetDefaultDictionary()
	assert.Same(t, dict, dict2)
}

func TestBackwardCompatibility(t *testing.T) {
	// Test that our new variables have the same values as the original RFC constants would
	expectedValues := map[uint8]string{
		1:  "User-Name",
		2:  "User-Password",
		4:  "NAS-IP-Address",
		5:  "NAS-Port",
		6:  "Service-Type",
		24: "State",
		25: "Class",
		26: "Vendor-Specific",
		27: "Session-Timeout",
		40: "Acct-Status-Type",
		44: "Acct-Session-Id",
		60: "CHAP-Challenge",
		61: "NAS-Port-Type",
		64: "Tunnel-Type",
		80: "Message-Authenticator",
	}

	dict := GetDefaultDictionary()
	for expectedType, expectedName := range expectedValues {
		actualName := dict.GetAttributeNameByType(expectedType)
		assert.Equal(t, expectedName, actualName,
			"Attribute type %d should have name %s", expectedType, expectedName)
	}

	// Test that our variables match the expected values
	assert.Equal(t, uint8(1), AttrUserName)
	assert.Equal(t, uint8(2), AttrUserPassword)
	assert.Equal(t, uint8(4), AttrNASIPAddress)
	assert.Equal(t, uint8(5), AttrNASPort)
	assert.Equal(t, uint8(6), AttrServiceType)
	assert.Equal(t, uint8(24), AttrState)
	assert.Equal(t, uint8(25), AttrClass)
	assert.Equal(t, uint8(26), AttrVendorSpecific)
	assert.Equal(t, uint8(27), AttrSessionTimeout)
	assert.Equal(t, uint8(40), AttrAcctStatusType)
	assert.Equal(t, uint8(44), AttrAcctSessionID)
	assert.Equal(t, uint8(60), AttrCHAPChallenge)
	assert.Equal(t, uint8(61), AttrNASPortType)
	assert.Equal(t, uint8(64), AttrTunnelType)
	assert.Equal(t, uint8(80), AttrMessageAuthenticator)
}

func TestAttributeUsageInCode(t *testing.T) {
	// Test that attributes can be used in switch statements (backward compatibility)
	testType := AttrUserName

	var result string
	switch testType {
	case AttrUserName:
		result = "User-Name"
	case AttrUserPassword:
		result = "User-Password"
	case AttrVendorSpecific:
		result = "Vendor-Specific"
	default:
		result = "Unknown"
	}

	assert.Equal(t, "User-Name", result)
}

func TestDictionaryInitialization(t *testing.T) {
	// Test that dictionary is initialized properly
	dict := GetDefaultDictionary()

	// Test that it has the expected attributes
	attr, found := dict.GetAttribute(1)
	assert.True(t, found)
	assert.Equal(t, "User-Name", attr.Name)

	attr, found = dict.GetAttribute(26)
	assert.True(t, found)
	assert.Equal(t, "Vendor-Specific", attr.Name)
}

func TestAllAttributesPresentInDictionary(t *testing.T) {
	// Test that all our variables correspond to actual dictionary entries
	dict := GetDefaultDictionary()

	attributesToTest := []struct {
		name  string
		value uint8
	}{
		{"User-Name", AttrUserName},
		{"User-Password", AttrUserPassword},
		{"NAS-IP-Address", AttrNASIPAddress},
		{"Service-Type", AttrServiceType},
		{"Vendor-Specific", AttrVendorSpecific},
		{"Acct-Status-Type", AttrAcctStatusType},
		{"CHAP-Challenge", AttrCHAPChallenge},
		{"Tunnel-Type", AttrTunnelType},
		{"Message-Authenticator", AttrMessageAuthenticator},
	}

	for _, test := range attributesToTest {
		attr, found := dict.GetAttribute(test.value)
		assert.True(t, found, "Attribute %s (type %d) should be found in dictionary", test.name, test.value)
		assert.Equal(t, test.name, attr.Name, "Attribute type %d should have name %s", test.value, test.name)
	}
}
