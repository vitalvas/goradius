package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNokiaSRStructCounterRoundTrip confirms a real registered Nokia SR
// accounting counter (a struct VSA with byte/byte/uint64 members) encodes into
// a packet and decodes back through the default dictionary.
func TestNokiaSRStructCounterRoundTrip(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccountingRequest, 7, dict)
	require.NoError(t, pkt.AddAttributeByName("nokia-sr-acct-i-inprof-octets-64", map[string]any{
		"nokia-sr-acct-i-inprof-octets-selection": uint8(0x80),
		"nokia-sr-acct-i-inprof-octets-id":        uint8(3),
		"nokia-sr-acct-i-inprof-octets":           uint64(0x0102030405060708),
	}))

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	vals := decoded.GetAttribute("nokia-sr-acct-i-inprof-octets-64")
	require.Len(t, vals, 1)
	children, err := vals[0].Children()
	require.NoError(t, err)
	assert.Equal(t, uint8(0x80), children["nokia-sr-acct-i-inprof-octets-selection"])
	assert.Equal(t, uint8(3), children["nokia-sr-acct-i-inprof-octets-id"])
	assert.Equal(t, uint64(0x0102030405060708), children["nokia-sr-acct-i-inprof-octets"])
}

func TestNokiaSRVendorDefinition(t *testing.T) {
	assert.NotNil(t, NokiaSRVendorDefinition)
	assert.Equal(t, uint32(6527), NokiaSRVendorDefinition.ID)
	assert.Equal(t, "nokia-sr", NokiaSRVendorDefinition.Name)
	assert.Len(t, NokiaSRVendorDefinition.Attributes, 190)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range NokiaSRVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("timetra access values", func(t *testing.T) {
		access, ok := attrMap["nokia-sr-timetra-access"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), access.Values["ftp"])
		assert.Equal(t, uint32(3), access.Values["both"])
	})

	t.Run("tunnel attributes carry tags", func(t *testing.T) {
		for _, name := range []string{
			"nokia-sr-tunnel-max-sessions", "nokia-sr-tunnel-idle-timeout",
			"nokia-sr-tunnel-avp-hiding", "nokia-sr-tunnel-challenge",
			"nokia-sr-tunnel-acct-policy", "nokia-sr-acct-interim-level",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.True(t, attr.HasTag, name)
		}
	})

	t.Run("lawful intercept uses tunnel-password encryption", func(t *testing.T) {
		for _, name := range []string{
			"nokia-sr-li-action", "nokia-sr-li-destination", "nokia-sr-li-fc",
			"nokia-sr-li-direction", "nokia-sr-li-intercept-id",
			"nokia-sr-li-session-id", "nokia-sr-apn-password",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.Equal(t, EncryptionTunnelPassword, attr.Encryption, name)
		}
	})

	t.Run("li-fc best-effort value is zero", func(t *testing.T) {
		fc, ok := attrMap["nokia-sr-li-fc"]
		require.True(t, ok)
		assert.Equal(t, uint32(0), fc.Values["be"])
		assert.Equal(t, uint32(7), fc.Values["nc"])
	})

	t.Run("accounting counters are structs with wide members", func(t *testing.T) {
		counter, ok := attrMap["nokia-sr-acct-i-inprof-octets-64"]
		require.True(t, ok)
		assert.Equal(t, DataTypeStruct, counter.DataType)
		require.Len(t, counter.Children, 3)
		assert.Equal(t, DataTypeByte, counter.Children[0].DataType)
		assert.Equal(t, DataTypeByte, counter.Children[1].DataType)
		assert.Equal(t, DataTypeInteger64, counter.Children[2].DataType)

		// HSMDA override counters use a short id + uint64 value.
		oc, ok := attrMap["nokia-sr-acct-oc-i-inprof-octets-64"]
		require.True(t, ok)
		assert.Equal(t, DataTypeStruct, oc.DataType)
		require.Len(t, oc.Children, 2)
		assert.Equal(t, DataTypeShort, oc.Children[0].DataType)
		assert.Equal(t, DataTypeInteger64, oc.Children[1].DataType)
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range NokiaSRVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
