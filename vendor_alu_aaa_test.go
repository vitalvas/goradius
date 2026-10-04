package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestALUAAAComboIPRoundTrip confirms a real registered ALU-AAA combo-ip VSA
// round-trips through the default dictionary for both IPv4 and IPv6, choosing
// the 4- or 16-octet width by address family.
func TestALUAAAComboIPRoundTrip(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	cases := map[string]string{
		"192.0.2.10":  "192.0.2.10",
		"2001:db8::5": "2001:db8::5",
	}
	for input, want := range cases {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 7, dict)
		require.NoError(t, pkt.AddAttributeByName("alu-aaa-address-0", input))

		raw, err := pkt.Encode()
		require.NoError(t, err)
		decoded, err := Decode(raw)
		require.NoError(t, err)
		decoded.Dict = dict

		vals := decoded.GetAttribute("alu-aaa-address-0")
		require.Len(t, vals, 1, input)
		ip, err := DecodeComboIP(vals[0].Value)
		require.NoError(t, err)
		assert.Equal(t, want, ip.String())
	}
}

func TestALUAAAVendorDefinition(t *testing.T) {
	assert.NotNil(t, ALUAAAVendorDefinition)
	assert.Equal(t, uint32(831), ALUAAAVendorDefinition.ID)
	assert.Equal(t, "alu-aaa", ALUAAAVendorDefinition.Name)
	assert.Len(t, ALUAAAVendorDefinition.Attributes, 64)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range ALUAAAVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("keys use tunnel-password encryption", func(t *testing.T) {
		for _, name := range []string{
			"alu-aaa-key-0", "alu-aaa-key-1", "alu-aaa-key-2", "alu-aaa-key-3",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.Equal(t, EncryptionTunnelPassword, attr.Encryption, name)
		}
	})

	t.Run("client error action values", func(t *testing.T) {
		action, ok := attrMap["alu-aaa-client-error-action"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), action.Values["ignore"])
		assert.Equal(t, uint32(2), action.Values["disconnect"])
	})

	t.Run("timestamps are date type", func(t *testing.T) {
		old, ok := attrMap["alu-aaa-old-timestamp"]
		require.True(t, ok)
		assert.Equal(t, DataTypeDate, old.DataType)
	})

	t.Run("all attributes stay unrestricted", func(t *testing.T) {
		for _, attr := range ALUAAAVendorDefinition.Attributes {
			assert.Equal(t, AttributeUsage(0), attr.Usage, attr.Name)
		}
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range ALUAAAVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
