package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRFC5580LocationRoundTrip confirms the RFC 5580 Location-Information
// struct (index, code, entity, two 64-bit times, and a trailing method
// string) encodes into a packet and decodes back through the default
// dictionary.
func TestRFC5580LocationRoundTrip(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessRequest, 7, dict)
	require.NoError(t, pkt.AddAttributeByName("location-information", map[string]any{
		"location-information-index":         uint16(1),
		"location-information-code":          uint8(1),
		"location-information-entity":        uint8(0),
		"location-information-sighting-time": uint64(1700000000),
		"location-information-ttl":           uint64(3600),
		"location-information-method":        "802.11",
	}))

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	vals := decoded.GetAttribute("location-information")
	require.Len(t, vals, 1)
	children, err := vals[0].Children()
	require.NoError(t, err)
	assert.Equal(t, uint16(1), children["location-information-index"])
	assert.Equal(t, uint8(1), children["location-information-code"])
	assert.Equal(t, uint64(1700000000), children["location-information-sighting-time"])
	assert.Equal(t, "802.11", children["location-information-method"])
}

// TestRFCAttributeTypeFixes pins the data-type corrections verified against
// the authoritative RFC dictionaries: MIP6-Feature-Vector is a 64-bit value,
// PKM-SAID is 16-bit, and the 6rd configuration TLV carries three sub-attrs.
func TestRFCAttributeTypeFixes(t *testing.T) {
	byName := make(map[string]*AttributeDefinition)
	for _, a := range StandardRFCAttributes {
		byName[a.Name] = a
	}

	require.Equal(t, DataTypeInteger64, byName["mip6-feature-vector"].DataType)
	require.Equal(t, DataTypeShort, byName["pkm-said"].DataType)

	sixrd := byName["ipv6-6rd-configuration"]
	require.NotNil(t, sixrd)
	require.Equal(t, DataTypeTLV, sixrd.DataType)
	require.Len(t, sixrd.Children, 3)
	assert.Equal(t, DataTypeInteger, sixrd.Children[0].DataType)
	assert.Equal(t, DataTypeIPv6Prefix, sixrd.Children[1].DataType)
	assert.Equal(t, DataTypeIPAddr, sixrd.Children[2].DataType)

	opc := byName["original-packet-code"]
	require.NotNil(t, opc)
	assert.True(t, opc.Extended)
	assert.Equal(t, uint32(43), opc.Values["coa-request"])
	assert.Equal(t, uint32(52), opc.Values["protocol-error"])
	require.NotNil(t, byName["response-length"])
}

func TestStandardRFCAttributes(t *testing.T) {
	assert.NotNil(t, StandardRFCAttributes)
	assert.NotEmpty(t, StandardRFCAttributes)

	// Check some well-known attributes
	nameMap := make(map[string]*AttributeDefinition)
	idMap := make(map[uint32]*AttributeDefinition)

	for _, attr := range StandardRFCAttributes {
		nameMap[attr.Name] = attr
		idMap[attr.ID] = attr
	}

	// Verify User-Name (ID 1)
	userNameAttr, exists := idMap[1]
	assert.True(t, exists, "user-name attribute should exist")
	if exists {
		assert.Equal(t, "user-name", userNameAttr.Name)
		assert.Equal(t, DataTypeString, userNameAttr.DataType)
	}

	// Verify User-Password (ID 2)
	userPassAttr, exists := idMap[2]
	assert.True(t, exists, "user-password attribute should exist")
	if exists {
		assert.Equal(t, "user-password", userPassAttr.Name)
		assert.Equal(t, DataTypeString, userPassAttr.DataType)
		assert.Equal(t, EncryptionUserPassword, userPassAttr.Encryption)
	}

	// Verify NAS-IP-Address (ID 4)
	nasIPAttr, exists := idMap[4]
	assert.True(t, exists, "nas-ip-address attribute should exist")
	if exists {
		assert.Equal(t, "nas-ip-address", nasIPAttr.Name)
		assert.Equal(t, DataTypeIPAddr, nasIPAttr.DataType)
	}

	// Verify Framed-IP-Address (ID 8)
	framedIPAttr, exists := idMap[8]
	assert.True(t, exists, "framed-ip-address attribute should exist")
	if exists {
		assert.Equal(t, "framed-ip-address", framedIPAttr.Name)
		assert.Equal(t, DataTypeIPAddr, framedIPAttr.DataType)
	}
}

func TestNoDuplicateStandardAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range StandardRFCAttributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestNoDuplicateStandardAttributeNames(t *testing.T) {
	seen := make(map[string]uint32)

	for _, attr := range StandardRFCAttributes {
		if existing, exists := seen[attr.Name]; exists {
			t.Errorf("Duplicate attribute name %s: ID %d and %d", attr.Name, existing, attr.ID)
		}
		seen[attr.Name] = attr.ID
	}
}
