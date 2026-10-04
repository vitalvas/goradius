package goradius

import (
	"bytes"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func structTestParent() *AttributeDefinition {
	return &AttributeDefinition{
		ID:       200,
		Name:     "test-struct",
		DataType: DataTypeStruct,
		Children: []*AttributeDefinition{
			{ID: 1, Name: "s-count", DataType: DataTypeInteger},
			{ID: 2, Name: "s-addr", DataType: DataTypeIPAddr},
			{ID: 3, Name: "s-label", DataType: DataTypeString, Size: 4},
		},
	}
}

func TestEncodeStruct(t *testing.T) {
	parent := structTestParent()

	t.Run("fixed-width members", func(t *testing.T) {
		out, err := EncodeStruct(parent, map[string]any{
			"s-count": uint32(1),
			"s-addr":  "10.0.0.1",
			"s-label": "ab",
		})
		require.NoError(t, err)
		// integer(4) + ipaddr(4) + string padded to 4 = 12 bytes
		require.Len(t, out, 12)
		assert.Equal(t, []byte{0, 0, 0, 1}, out[0:4])
		assert.Equal(t, []byte{10, 0, 0, 1}, out[4:8])
		assert.Equal(t, []byte{'a', 'b', 0, 0}, out[8:12]) // zero-padded to Size
	})

	t.Run("missing member", func(t *testing.T) {
		_, err := EncodeStruct(parent, map[string]any{"s-count": uint32(1)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing member")
	})

	t.Run("non-trailing variable member without size", func(t *testing.T) {
		// A variable-width member with no Size is only valid as the final
		// member; here it is followed by another member, so it must error.
		bad := &AttributeDefinition{
			Name:     "bad-struct",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "bad-str", DataType: DataTypeString}, // no Size, not last
				{ID: 2, Name: "bad-int", DataType: DataTypeInteger},
			},
		}
		_, err := EncodeStruct(bad, map[string]any{"bad-str": "x", "bad-int": uint32(1)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be the final member")
	})

	t.Run("oversized variable member", func(t *testing.T) {
		_, err := EncodeStruct(parent, map[string]any{
			"s-count": uint32(1),
			"s-addr":  "10.0.0.1",
			"s-label": "hello", // declared Size is 4
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds declared size")
	})

	t.Run("nil parent", func(t *testing.T) {
		_, err := EncodeStruct(nil, map[string]any{})
		require.Error(t, err)
	})

	t.Run("bad member value", func(t *testing.T) {
		_, err := EncodeStruct(parent, map[string]any{
			"s-count": "not-a-number",
			"s-addr":  "10.0.0.1",
			"s-label": "ab",
		})
		require.Error(t, err)
	})
}

func TestDecodeStruct(t *testing.T) {
	parent := structTestParent()

	t.Run("fixed-width members", func(t *testing.T) {
		data := []byte{0, 0, 0, 9, 192, 168, 1, 5, 'h', 'i', 0, 0}
		m, err := DecodeStruct(parent, data)
		require.NoError(t, err)
		assert.Equal(t, uint32(9), m["s-count"])
		assert.True(t, net.ParseIP("192.168.1.5").Equal(m["s-addr"].(net.IP)))
		assert.Equal(t, string([]byte{'h', 'i', 0, 0}), m["s-label"])
	})

	t.Run("truncated", func(t *testing.T) {
		_, err := DecodeStruct(parent, []byte{0, 0, 0, 9, 192, 168})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "truncated")
	})

	t.Run("trailing bytes", func(t *testing.T) {
		data := []byte{0, 0, 0, 9, 192, 168, 1, 5, 'h', 'i', 0, 0, 0xff}
		_, err := DecodeStruct(parent, data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trailing bytes")
	})

	t.Run("nil parent", func(t *testing.T) {
		_, err := DecodeStruct(nil, []byte{})
		require.Error(t, err)
	})

	t.Run("non-trailing variable member without size", func(t *testing.T) {
		bad := &AttributeDefinition{
			Name:     "bad-struct",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "bad-str", DataType: DataTypeString}, // no Size, not last
				{ID: 2, Name: "bad-int", DataType: DataTypeInteger},
			},
		}
		_, err := DecodeStruct(bad, []byte{1, 2, 3, 4, 5, 6, 7, 8})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must be the final member")
	})

	t.Run("trailing variable member consumes remainder", func(t *testing.T) {
		parent := &AttributeDefinition{
			Name:     "tail-struct",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "ts-int", DataType: DataTypeInteger},
				{ID: 2, Name: "ts-str", DataType: DataTypeString}, // no Size, last
			},
		}
		decoded, err := DecodeStruct(parent, []byte{0, 0, 0, 9, 'h', 'i'})
		require.NoError(t, err)
		assert.Equal(t, uint32(9), decoded["ts-int"])
		assert.Equal(t, "hi", decoded["ts-str"])
	})
}

func TestStructRoundTrip(t *testing.T) {
	parent := &AttributeDefinition{
		ID:       201,
		Name:     "rt-struct",
		DataType: DataTypeStruct,
		Children: []*AttributeDefinition{
			{ID: 1, Name: "rt-int", DataType: DataTypeInteger},
			{ID: 2, Name: "rt-v6", DataType: DataTypeIPv6Addr},
			{ID: 3, Name: "rt-str", DataType: DataTypeString, Size: 8},
		},
	}

	in := map[string]any{
		"rt-int": uint32(305419896),
		"rt-v6":  "2001:db8::abcd",
		"rt-str": "payload",
	}

	encoded, err := EncodeStruct(parent, in)
	require.NoError(t, err)
	require.Len(t, encoded, 4+16+8)

	decoded, err := DecodeStruct(parent, encoded)
	require.NoError(t, err)
	assert.Equal(t, uint32(305419896), decoded["rt-int"])
	assert.True(t, net.ParseIP("2001:db8::abcd").Equal(decoded["rt-v6"].(net.IP)))
	assert.Equal(t, "payload\x00", decoded["rt-str"])
}

// TestStructTrailingVariableMember covers a struct whose final member is a
// string with no Size: it is written at its natural length and consumes the
// remaining bytes on decode (the RFC 5580 Location-Information layout).
func TestStructTrailingVariableMember(t *testing.T) {
	parent := &AttributeDefinition{
		Name:     "loc",
		DataType: DataTypeStruct,
		Children: []*AttributeDefinition{
			{Name: "index", DataType: DataTypeShort},
			{Name: "code", DataType: DataTypeByte},
			{Name: "ttl", DataType: DataTypeInteger64},
			{Name: "method", DataType: DataTypeString},
		},
	}

	encoded, err := EncodeStruct(parent, map[string]any{
		"index":  uint16(5),
		"code":   uint8(1),
		"ttl":    uint64(3600),
		"method": "802.11",
	})
	require.NoError(t, err)
	// 2 + 1 + 8 + len("802.11")
	assert.Len(t, encoded, 2+1+8+6)

	decoded, err := DecodeStruct(parent, encoded)
	require.NoError(t, err)
	assert.Equal(t, uint16(5), decoded["index"])
	assert.Equal(t, uint8(1), decoded["code"])
	assert.Equal(t, uint64(3600), decoded["ttl"])
	assert.Equal(t, "802.11", decoded["method"])
}

func TestStructTrailingVariableMemberMustBeLast(t *testing.T) {
	parent := &AttributeDefinition{
		Name:     "bad",
		DataType: DataTypeStruct,
		Children: []*AttributeDefinition{
			{Name: "tail", DataType: DataTypeString},
			{Name: "after", DataType: DataTypeByte},
		},
	}
	_, err := EncodeStruct(parent, map[string]any{"tail": "x", "after": uint8(1)})
	assert.Error(t, err)
}

func TestStructBitMembers(t *testing.T) {
	// 3 + 1 + 4 bits = one octet, packed MSB-first.
	parent := &AttributeDefinition{
		Name:     "bits-struct",
		DataType: DataTypeStruct,
		Children: []*AttributeDefinition{
			{ID: 1, Name: "bm-spare", DataType: DataTypeBits, Bits: 3},
			{ID: 2, Name: "bm-flag", DataType: DataTypeBits, Bits: 1},
			{ID: 3, Name: "bm-code", DataType: DataTypeBits, Bits: 4},
		},
	}

	enc, err := EncodeStruct(parent, map[string]any{
		"bm-spare": uint8(0b101),
		"bm-flag":  uint8(1),
		"bm-code":  uint8(0b0110),
	})
	require.NoError(t, err)
	require.Equal(t, []byte{0xB6}, enc) // 101 1 0110

	dec, err := DecodeStruct(parent, enc)
	require.NoError(t, err)
	assert.Equal(t, uint64(0b101), dec["bm-spare"])
	assert.Equal(t, uint64(1), dec["bm-flag"])
	assert.Equal(t, uint64(0b0110), dec["bm-code"])

	t.Run("bits must fill whole octets", func(t *testing.T) {
		bad := &AttributeDefinition{
			Name:     "odd-bits",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "ob-a", DataType: DataTypeBits, Bits: 3},
			},
		}
		_, err := EncodeStruct(bad, map[string]any{"ob-a": uint8(1)})
		assert.Error(t, err)
	})

	t.Run("value overflow rejected", func(t *testing.T) {
		_, err := EncodeStruct(parent, map[string]any{
			"bm-spare": uint8(8), // needs 4 bits, field is 3
			"bm-flag":  uint8(0),
			"bm-code":  uint8(0),
		})
		assert.Error(t, err)
	})
}

func TestStructUnionMember(t *testing.T) {
	parent := &AttributeDefinition{
		Name:     "u-struct",
		DataType: DataTypeStruct,
		Children: []*AttributeDefinition{
			{ID: 1, Name: "u-type", DataType: DataTypeByte},
			{
				ID:       2,
				Name:     "u-data",
				DataType: DataTypeUnion,
				UnionKey: "u-type",
				Children: []*AttributeDefinition{
					{
						ID:       0,
						Name:     "u-v0",
						DataType: DataTypeStruct,
						Children: []*AttributeDefinition{
							{ID: 1, Name: "u-v0-a", DataType: DataTypeShort},
						},
					},
					{
						ID:       1,
						Name:     "u-v1",
						DataType: DataTypeStruct,
						Children: []*AttributeDefinition{
							{ID: 1, Name: "u-v1-x", DataType: DataTypeShort},
							{ID: 2, Name: "u-v1-y", DataType: DataTypeShort},
						},
					},
				},
			},
		},
	}

	t.Run("variant 0 selected by key", func(t *testing.T) {
		enc, err := EncodeStruct(parent, map[string]any{
			"u-type": uint8(0),
			"u-data": map[string]any{"u-v0-a": uint16(0xABCD)},
		})
		require.NoError(t, err)
		assert.Equal(t, []byte{0x00, 0xAB, 0xCD}, enc)

		dec, err := DecodeStruct(parent, enc)
		require.NoError(t, err)
		assert.Equal(t, uint8(0), dec["u-type"])
		sub := dec["u-data"].(map[string]any)
		assert.Equal(t, uint16(0xABCD), sub["u-v0-a"])
	})

	t.Run("unknown key errors", func(t *testing.T) {
		_, err := EncodeStruct(parent, map[string]any{
			"u-type": uint8(9),
			"u-data": map[string]any{},
		})
		assert.Error(t, err)
	})
}

func TestPacketStructRoundTrip(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   9,
		Name: "cisco",
		Attributes: []*AttributeDefinition{
			{
				ID:       221,
				Name:     "cisco-struct-example",
				DataType: DataTypeStruct,
				Children: []*AttributeDefinition{
					{ID: 1, Name: "cs-int", DataType: DataTypeInteger},
					{ID: 2, Name: "cs-ip", DataType: DataTypeIPAddr},
				},
			},
		},
	}))

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("cisco-struct-example", map[string]any{
		"cs-int": uint32(77),
		"cs-ip":  "203.0.113.9",
	}))

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	vals := decoded.GetAttribute("cisco-struct-example")
	require.Len(t, vals, 1)
	children, err := vals[0].Children()
	require.NoError(t, err)
	assert.Equal(t, uint32(77), children["cs-int"])
	assert.True(t, net.ParseIP("203.0.113.9").Equal(children["cs-ip"].(net.IP)))
}

func BenchmarkEncodeStruct(b *testing.B) {
	parent := structTestParent()
	values := map[string]any{
		"s-count": uint32(1),
		"s-addr":  "10.0.0.1",
		"s-label": "ab",
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeStruct(parent, values)
	}
}

func BenchmarkDecodeStruct(b *testing.B) {
	parent := structTestParent()
	data, err := EncodeStruct(parent, map[string]any{
		"s-count": uint32(1),
		"s-addr":  "10.0.0.1",
		"s-label": "ab",
	})
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeStruct(parent, data)
	}
}

// FuzzDecodeStruct ensures DecodeStruct never panics on arbitrary input and that a
// successful decode re-encodes to exactly the same bytes (fixed-layout stability).
func FuzzDecodeStruct(f *testing.F) {
	parent := structTestParent()

	for _, seed := range [][]byte{
		{},
		{0, 0, 0, 9, 192, 168, 1, 5, 'h', 'i', 0, 0},       // valid 12-byte layout
		{0, 0, 0, 9, 192, 168},                             // truncated
		{0, 0, 0, 9, 192, 168, 1, 5, 'h', 'i', 0, 0, 0xff}, // trailing byte
		make([]byte, 12),
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeStruct(parent, data)
		if err != nil {
			return // malformed input rejected cleanly
		}

		reencoded, err := EncodeStruct(parent, decoded)
		if err != nil {
			t.Fatalf("re-encode of decoded struct failed: %v", err)
		}
		if !bytes.Equal(reencoded, data) {
			t.Fatalf("struct round-trip mismatch: in=%x out=%x", data, reencoded)
		}
	})
}
