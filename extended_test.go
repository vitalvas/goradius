package goradius

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// extID packs an RFC 6929 base type and extended type into a single attribute ID.
func extID(base, ext uint8) uint32 {
	return uint32(base)*ExtendedIDShift + uint32(ext)
}

func TestNewExtendedAttribute(t *testing.T) {
	t.Run("builds short extended wire format", func(t *testing.T) {
		attr, err := NewExtendedAttribute(241, 5, []byte("abc"))
		require.NoError(t, err)
		assert.Equal(t, uint8(241), attr.Type)
		// Length = header(2) + ext-type(1) + value(3) = 6
		assert.Equal(t, uint8(6), attr.Length)
		assert.Equal(t, []byte{5, 'a', 'b', 'c'}, attr.Value)
	})

	t.Run("rejects long extended base type", func(t *testing.T) {
		_, err := NewExtendedAttribute(245, 1, []byte("x"))
		require.Error(t, err)
	})

	t.Run("rejects non-extended base type", func(t *testing.T) {
		_, err := NewExtendedAttribute(100, 1, []byte("x"))
		require.Error(t, err)
	})

	t.Run("rejects oversized value", func(t *testing.T) {
		_, err := NewExtendedAttribute(241, 1, bytes.Repeat([]byte{0}, MaxShortExtendedValueLength+1))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})
}

func TestParseExtendedAttribute(t *testing.T) {
	t.Run("round trip", func(t *testing.T) {
		attr, err := NewExtendedAttribute(243, 9, []byte("payload"))
		require.NoError(t, err)
		et, value, err := ParseExtendedAttribute(attr)
		require.NoError(t, err)
		assert.Equal(t, uint8(9), et)
		assert.Equal(t, []byte("payload"), value)
	})

	t.Run("rejects wrong type", func(t *testing.T) {
		_, _, err := ParseExtendedAttribute(&Attribute{Type: 245, Value: []byte{1, 2}})
		require.Error(t, err)
	})

	t.Run("rejects empty value", func(t *testing.T) {
		_, _, err := ParseExtendedAttribute(&Attribute{Type: 241, Value: nil})
		require.Error(t, err)
	})
}

func extendedDict(t *testing.T) *Dictionary {
	t.Helper()
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
		{ID: extID(241, 1), Name: "ext-short-string", DataType: DataTypeString, Extended: true},
		{ID: extID(241, 2), Name: "ext-short-integer", DataType: DataTypeInteger, Extended: true},
		{ID: extID(245, 1), Name: "ext-long-octets", DataType: DataTypeOctets, Extended: true},
	}))
	return dict
}

func TestPacketShortExtendedRoundTrip(t *testing.T) {
	dict := extendedDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("ext-short-string", "hello"))
	require.NoError(t, pkt.AddAttributeByName("ext-short-integer", uint32(99)))

	// Both are standard-space extended attributes carried with base type 241.
	require.Len(t, pkt.Attributes, 2)
	assert.Equal(t, uint8(241), pkt.Attributes[0].Type)
	assert.Equal(t, uint8(241), pkt.Attributes[1].Type)

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	strVals := decoded.GetAttribute("ext-short-string")
	require.Len(t, strVals, 1)
	assert.Equal(t, "hello", strVals[0].String())

	intVals := decoded.GetAttribute("ext-short-integer")
	require.Len(t, intVals, 1)
	assert.Equal(t, "99", intVals[0].String())
}

func TestPacketMixedStandardAndExtended(t *testing.T) {
	dict := extendedDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 3, dict)
	require.NoError(t, pkt.AddAttributeByName("user-name", "bob"))
	require.NoError(t, pkt.AddAttributeByName("ext-short-string", "ext"))

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	assert.Equal(t, "bob", decoded.GetAttributeString("user-name"))
	assert.Equal(t, "ext", decoded.GetAttributeString("ext-short-string"))
}

func TestNewLongExtendedAttributes(t *testing.T) {
	t.Run("single fragment when small", func(t *testing.T) {
		attrs, err := NewLongExtendedAttributes(245, 1, []byte("short"))
		require.NoError(t, err)
		require.Len(t, attrs, 1)
		assert.Equal(t, uint8(245), attrs[0].Type)
		// ext-type, flags(0, no More), value
		assert.Equal(t, []byte{1, 0, 's', 'h', 'o', 'r', 't'}, attrs[0].Value)
	})

	t.Run("fragments large value with More bit", func(t *testing.T) {
		value := bytes.Repeat([]byte{0xAB}, MaxLongExtendedValueLength+10)
		attrs, err := NewLongExtendedAttributes(246, 7, value)
		require.NoError(t, err)
		require.Len(t, attrs, 2)

		// First fragment: More bit set, full chunk.
		assert.Equal(t, uint8(7), attrs[0].Value[0])
		assert.Equal(t, uint8(LongExtendedMoreBit), attrs[0].Value[1])
		assert.Len(t, attrs[0].Value[2:], MaxLongExtendedValueLength)

		// Last fragment: More bit clear.
		assert.Equal(t, uint8(7), attrs[1].Value[0])
		assert.Equal(t, uint8(0), attrs[1].Value[1])
		assert.Len(t, attrs[1].Value[2:], 10)
	})

	t.Run("rejects short extended base type", func(t *testing.T) {
		_, err := NewLongExtendedAttributes(241, 1, []byte("x"))
		require.Error(t, err)
	})
}

func TestPacketLongExtendedRoundTrip(t *testing.T) {
	dict := extendedDict(t)

	t.Run("no fragmentation", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		payload := []byte("small-long-ext")
		require.NoError(t, pkt.AddAttributeByName("ext-long-octets", payload))
		require.Len(t, pkt.Attributes, 1)

		raw, err := pkt.Encode()
		require.NoError(t, err)
		decoded, err := Decode(raw)
		require.NoError(t, err)
		decoded.Dict = dict

		vals := decoded.GetAttribute("ext-long-octets")
		require.Len(t, vals, 1)
		assert.Equal(t, payload, vals[0].Value)
	})

	t.Run("fragmented reassembly", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 2, dict)
		payload := bytes.Repeat([]byte{0xCD}, 600)
		require.NoError(t, pkt.AddAttributeByName("ext-long-octets", payload))
		// 600 bytes / 251 per fragment => 3 fragments.
		require.Len(t, pkt.Attributes, 3)

		raw, err := pkt.Encode()
		require.NoError(t, err)
		decoded, err := Decode(raw)
		require.NoError(t, err)
		decoded.Dict = dict

		vals := decoded.GetAttribute("ext-long-octets")
		require.Len(t, vals, 1)
		assert.Equal(t, payload, vals[0].Value)
	})

	t.Run("1000 byte round trip", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 4, dict)
		payload := []byte(strings.Repeat("Z", 1000))
		require.NoError(t, pkt.AddAttributeByName("ext-long-octets", payload))

		raw, err := pkt.Encode()
		require.NoError(t, err)
		decoded, err := Decode(raw)
		require.NoError(t, err)
		decoded.Dict = dict

		vals := decoded.GetAttribute("ext-long-octets")
		require.Len(t, vals, 1)
		assert.Equal(t, payload, vals[0].Value)
	})
}

func BenchmarkNewExtendedAttribute(b *testing.B) {
	value := []byte("extended-value")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = NewExtendedAttribute(241, 1, value)
	}
}

func BenchmarkParseExtendedAttribute(b *testing.B) {
	attr, err := NewExtendedAttribute(241, 1, []byte("extended-value"))
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, _, _ = ParseExtendedAttribute(attr)
	}
}

func BenchmarkNewLongExtendedAttributes(b *testing.B) {
	value := bytes.Repeat([]byte{0xAB}, 600)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = NewLongExtendedAttributes(245, 1, value)
	}
}

// FuzzParseExtendedAttribute ensures parsing a short extended attribute from arbitrary
// bytes never panics and round-trips cleanly for the valid cases.
func FuzzParseExtendedAttribute(f *testing.F) {
	f.Add([]byte{5, 'a', 'b', 'c'})
	f.Add([]byte{0})
	f.Add([]byte{})
	f.Add([]byte(strings.Repeat("x", MaxShortExtendedValueLength+1)))

	f.Fuzz(func(t *testing.T, value []byte) {
		// Build a well-formed short extended attribute (type 241) around the fuzzed value,
		// then verify parse recovers the original value.
		attr := &Attribute{Type: 241, Value: value}
		extType, parsed, err := ParseExtendedAttribute(attr)
		if err != nil {
			return
		}
		require.NotEmpty(t, value)
		assert.Equal(t, value[0], extType)
		assert.Equal(t, value[1:], parsed)
	})
}

// FuzzLongExtendedRoundTrip ensures fragmentation and reassembly of long extended
// attributes is lossless for arbitrary payloads.
func FuzzLongExtendedRoundTrip(f *testing.F) {
	f.Add([]byte("short"))
	f.Add(bytes.Repeat([]byte{0xCD}, 600))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, payload []byte) {
		attrs, err := NewLongExtendedAttributes(245, 7, payload)
		require.NoError(t, err)

		var reassembled []byte
		for i, attr := range attrs {
			et, more, frag, err := parseLongExtendedFragment(attr)
			require.NoError(t, err)
			assert.Equal(t, uint8(7), et)
			assert.Equal(t, i < len(attrs)-1, more, "More bit set on all but last fragment")
			reassembled = append(reassembled, frag...)
		}

		if len(payload) == 0 {
			assert.Empty(t, reassembled)
			return
		}
		assert.Equal(t, payload, reassembled)
	})
}
