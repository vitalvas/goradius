package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestThreeGPPVendorDefinition(t *testing.T) {
	assert.NotNil(t, ThreeGPPVendorDefinition)
	assert.Equal(t, uint32(10415), ThreeGPPVendorDefinition.ID)
	assert.Equal(t, "3gpp", ThreeGPPVendorDefinition.Name)
	assert.Len(t, ThreeGPPVendorDefinition.Attributes, 31)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range ThreeGPPVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("pdp type and rat type enums", func(t *testing.T) {
		pdp, ok := attrMap["3gpp-pdp-type"]
		require.True(t, ok)
		assert.Equal(t, uint32(3), pdp.Values["ipv4v6"])

		rat, ok := attrMap["3gpp-rat-type"]
		require.True(t, ok)
		assert.Equal(t, DataTypeByte, rat.DataType)
		assert.Equal(t, uint32(6), rat.Values["eutran"])
		assert.Equal(t, uint32(51), rat.Values["nr"])
	})

	t.Run("imsi and charging id", func(t *testing.T) {
		assert.Equal(t, DataTypeString, attrMap["3gpp-imsi"].DataType)
		assert.Equal(t, DataTypeInteger, attrMap["3gpp-charging-id"].DataType)
	})

	t.Run("ipv6 dns servers is an array", func(t *testing.T) {
		dns, ok := attrMap["3gpp-ipv6-dns-servers"]
		require.True(t, ok)
		assert.Equal(t, DataTypeIPv6Addr, dns.DataType)
		assert.True(t, dns.Array)
	})

	t.Run("modeled structs with trailing octets", func(t *testing.T) {
		tz, ok := attrMap["3gpp-ms-timezone"]
		require.True(t, ok)
		assert.Equal(t, DataTypeStruct, tz.DataType)
		require.Len(t, tz.Children, 2)
		assert.Equal(t, DataTypeByte, tz.Children[0].DataType)
		assert.Equal(t, DataTypeOctets, tz.Children[1].DataType)

		pf, ok := attrMap["3gpp-packet-filter"]
		require.True(t, ok)
		assert.Equal(t, DataTypeStruct, pf.DataType)
		require.Len(t, pf.Children, 5)
		assert.Equal(t, uint32(1), pf.Children[3].Values["uplink"])
	})

	t.Run("user-location-info union struct", func(t *testing.T) {
		uli, ok := attrMap["3gpp-user-location-info"]
		require.True(t, ok)
		assert.Equal(t, DataTypeStruct, uli.DataType)
		require.Len(t, uli.Children, 3)
		union := uli.Children[2]
		assert.Equal(t, DataTypeUnion, union.DataType)
		assert.Equal(t, "3gpp-uli-type", union.UnionKey)
		assert.Len(t, union.Children, 7) // cgi, sai, rai, lai, tai, ecgi, tai-ecgi
	})

	t.Run("secondary-rat-usage bit struct", func(t *testing.T) {
		s, ok := attrMap["3gpp-secondary-rat-usage"]
		require.True(t, ok)
		assert.Equal(t, DataTypeStruct, s.DataType)
		assert.Equal(t, DataTypeBits, s.Children[0].DataType)
		assert.Equal(t, 3, s.Children[0].Bits)
		assert.Equal(t, DataTypeInteger64, s.Children[5].DataType)
	})

	t.Run("user-location-info union encodes byte-exact", func(t *testing.T) {
		uli := attrMap["3gpp-user-location-info"]
		// Type=1 (SAI) + PLMN-ID(3) + SAI{lac=0x1111, sac=0x2222}.
		enc, err := EncodeStruct(uli, map[string]any{
			"3gpp-uli-type":    uint8(1),
			"3gpp-uli-plmn-id": []byte{0x12, 0x34, 0x56},
			"3gpp-uli-data": map[string]any{
				"3gpp-uli-sai-lac": uint16(0x1111),
				"3gpp-uli-sai-sac": uint16(0x2222),
			},
		})
		require.NoError(t, err)
		assert.Equal(t, []byte{0x01, 0x12, 0x34, 0x56, 0x11, 0x11, 0x22, 0x22}, enc)

		dec, err := DecodeStruct(uli, enc)
		require.NoError(t, err)
		assert.Equal(t, uint8(1), dec["3gpp-uli-type"])
		sub, ok := dec["3gpp-uli-data"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t, uint16(0x1111), sub["3gpp-uli-sai-lac"])
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range ThreeGPPVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
