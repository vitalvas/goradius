package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEVSAttribute(t *testing.T) {
	t.Run("builds EVS wire format", func(t *testing.T) {
		attr, err := NewEVSAttribute(241, 9, 1, []byte("x"))
		require.NoError(t, err)
		assert.Equal(t, uint8(241), attr.Type)
		// ext-type(26) + vendor-id(4=9) + vendor-type(1) + value("x")
		assert.Equal(t, []byte{EVSExtendedType, 0, 0, 0, 9, 1, 'x'}, attr.Value)
	})

	t.Run("rejects long extended base type", func(t *testing.T) {
		_, err := NewEVSAttribute(245, 9, 1, []byte("x"))
		require.Error(t, err)
	})
}

func TestParseEVS(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		attr, err := NewEVSAttribute(242, 311, 7, []byte("data"))
		require.NoError(t, err)

		vendorID, vendorType, value, err := ParseEVS(attr)
		require.NoError(t, err)
		assert.Equal(t, uint32(311), vendorID)
		assert.Equal(t, uint8(7), vendorType)
		assert.Equal(t, []byte("data"), value)
	})

	t.Run("rejects non-EVS extended attribute", func(t *testing.T) {
		attr, err := NewExtendedAttribute(241, 5, []byte("not-evs"))
		require.NoError(t, err)
		_, _, _, err = ParseEVS(attr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not EVS")
	})

	t.Run("rejects short payload", func(t *testing.T) {
		attr, err := NewExtendedAttribute(241, EVSExtendedType, []byte{0, 0})
		require.NoError(t, err)
		_, _, _, err = ParseEVS(attr)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "too short")
	})
}

func evsDict(t *testing.T) *Dictionary {
	t.Helper()
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		// Scalar (octets) EVS: base 241, ext type 26, vendor 9 / vendor-type 1.
		{
			ID:         extID(241, EVSExtendedType),
			Name:       "evs-raw",
			DataType:   DataTypeEVS,
			Extended:   true,
			VendorID:   9,
			VendorType: 1,
		},
	}))
	// A separate definition for an EVS carrying a TLV, using vendor-type 2 so it is
	// distinguishable on the wire. It cannot share the packed ID of evs-raw, so use
	// a different base/ext combination is unnecessary: distinguish by VendorType.
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:         extID(242, EVSExtendedType),
			Name:       "evs-tlv",
			DataType:   DataTypeEVS,
			Extended:   true,
			VendorID:   9,
			VendorType: 2,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "evs-tlv-name", DataType: DataTypeString},
				{ID: 2, Name: "evs-tlv-count", DataType: DataTypeInteger},
			},
		},
	}))
	return dict
}

func TestPacketEVSRoundTrip(t *testing.T) {
	dict := evsDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("evs-raw", []byte{0xDE, 0xAD, 0xBE, 0xEF}))
	require.Len(t, pkt.Attributes, 1)
	assert.Equal(t, uint8(241), pkt.Attributes[0].Type)

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	vals := decoded.GetAttribute("evs-raw")
	require.Len(t, vals, 1)
	assert.True(t, vals[0].IsVSA)
	assert.Equal(t, uint32(9), vals[0].VendorID)
	assert.Equal(t, uint32(1), vals[0].VendorType)
	assert.Equal(t, []byte{0xDE, 0xAD, 0xBE, 0xEF}, vals[0].Value)
}

func TestPacketEVSWithTLVChild(t *testing.T) {
	dict := evsDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 2, dict)
	require.NoError(t, pkt.AddAttributeByName("evs-tlv", map[string]any{
		"evs-tlv-name":  "svc",
		"evs-tlv-count": uint32(3),
	}))

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	vals := decoded.GetAttribute("evs-tlv")
	require.Len(t, vals, 1)
	assert.Equal(t, uint32(9), vals[0].VendorID)
	assert.Equal(t, uint32(2), vals[0].VendorType)

	children, err := vals[0].Children()
	require.NoError(t, err)
	assert.Equal(t, "svc", children["evs-tlv-name"])
	assert.Equal(t, uint32(3), children["evs-tlv-count"])
}

func TestPacketEVSTypeErrors(t *testing.T) {
	dict := evsDict(t)

	t.Run("raw EVS requires bytes", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		err := pkt.AddAttributeByName("evs-raw", "not-bytes")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires a []byte")
	})

	t.Run("tlv EVS requires map", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		err := pkt.AddAttributeByName("evs-tlv", []byte{1, 2})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires a map")
	})
}

func BenchmarkNewEVSAttribute(b *testing.B) {
	value := []byte("evs-value")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = NewEVSAttribute(241, 9, 1, value)
	}
}

func BenchmarkParseEVS(b *testing.B) {
	attr, err := NewEVSAttribute(241, 9, 1, []byte("evs-value"))
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, _, _, _ = ParseEVS(attr)
	}
}

// FuzzParseEVS ensures parsing an EVS attribute from arbitrary bytes never panics, and
// that NewEVSAttribute -> ParseEVS round-trips for arbitrary vendor data.
func FuzzParseEVS(f *testing.F) {
	f.Add(uint32(9), uint8(1), []byte("data"))
	f.Add(uint32(0), uint8(0), []byte{})
	f.Add(uint32(4294967295), uint8(255), []byte{0xDE, 0xAD, 0xBE, 0xEF})

	f.Fuzz(func(t *testing.T, vendorID uint32, vendorType uint8, value []byte) {
		attr, err := NewEVSAttribute(241, vendorID, vendorType, value)
		if err != nil {
			return // value too large for a single attribute — rejected cleanly
		}

		gotVendorID, gotVendorType, gotValue, err := ParseEVS(attr)
		require.NoError(t, err)
		assert.Equal(t, vendorID, gotVendorID)
		assert.Equal(t, vendorType, gotVendorType)
		if len(value) == 0 {
			assert.Empty(t, gotValue)
			return
		}
		assert.Equal(t, value, gotValue)
	})
}

// FuzzParseEVSRaw ensures ParseEVS tolerates arbitrary raw attribute payloads without panicking.
func FuzzParseEVSRaw(f *testing.F) {
	f.Add([]byte{EVSExtendedType, 0, 0, 0, 9, 1, 'x'})
	f.Add([]byte{EVSExtendedType, 0, 0})
	f.Add([]byte{5, 0, 0, 0, 9, 1})
	f.Add([]byte{})

	f.Fuzz(func(_ *testing.T, payload []byte) {
		attr := &Attribute{Type: 241, Value: payload}
		_, _, _, _ = ParseEVS(attr) // must not panic
	})
}
