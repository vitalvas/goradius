package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlcatelESAMVendorDefinition(t *testing.T) {
	assert.NotNil(t, AlcatelESAMVendorDefinition)
	assert.Equal(t, uint32(637), AlcatelESAMVendorDefinition.ID)
	assert.Equal(t, "alcatel-esam", AlcatelESAMVendorDefinition.Name)
	assert.Equal(t, uint8(2), AlcatelESAMVendorDefinition.TypeOctets)
	assert.Equal(t, uint8(1), AlcatelESAMVendorDefinition.LengthOctets)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range AlcatelESAMVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("two octet type ids preserved", func(t *testing.T) {
		vrf, ok := attrMap["alcatel-esam-vrf-name"]
		require.True(t, ok)
		assert.Equal(t, uint32(0x0700), vrf.ID)

		xdsl, ok := attrMap["alcatel-esam-a-al-xdsl"]
		require.True(t, ok)
		assert.Equal(t, uint32(0x0716), xdsl.ID)
	})

	t.Run("termination cause values", func(t *testing.T) {
		tc, ok := attrMap["alcatel-esam-termination-cause"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), tc.Values["unknown-vrf"])
		assert.Equal(t, uint32(14), tc.Values["missing-attributes"])
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range AlcatelESAMVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID 0x%x: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}

// TestAlcatelESAMWireFormat verifies the format=2,1 header round-trips through
// a full packet encode/decode with the default dictionary.
func TestAlcatelESAMWireFormat(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 7, dict)
	require.NoError(t, pkt.AddAttributeByName("alcatel-esam-vrf-name", "customer-vrf"))

	// The encoded VSA must carry a 2-octet vendor type (0x0700).
	require.Len(t, pkt.Attributes, 1)
	vsaValue := pkt.Attributes[0].Value
	// Vendor-ID(4) + Vendor-Type(2) + Vendor-Length(1) + data
	require.GreaterOrEqual(t, len(vsaValue), 7)
	vendorID := uint32(vsaValue[0])<<24 | uint32(vsaValue[1])<<16 | uint32(vsaValue[2])<<8 | uint32(vsaValue[3])
	assert.Equal(t, uint32(637), vendorID)
	vendorType := uint32(vsaValue[4])<<8 | uint32(vsaValue[5])
	assert.Equal(t, uint32(0x0700), vendorType)
	assert.Equal(t, uint8(len(vsaValue)-4), vsaValue[6], "vendor-length counts type+length+data")

	// Decode the full packet back and confirm the value survives.
	encoded, err := pkt.Encode()
	require.NoError(t, err)

	decoded, err := Decode(encoded)
	require.NoError(t, err)
	decoded.Dict = dict

	values := decoded.GetAttribute("alcatel-esam-vrf-name")
	require.Len(t, values, 1)
	assert.Equal(t, "customer-vrf", string(values[0].Value))
}
