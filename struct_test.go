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

	t.Run("variable member without size", func(t *testing.T) {
		bad := &AttributeDefinition{
			Name:     "bad-struct",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "bad-str", DataType: DataTypeString}, // no Size
			},
		}
		_, err := EncodeStruct(bad, map[string]any{"bad-str": "x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires a Size hint")
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

	t.Run("variable member without size", func(t *testing.T) {
		bad := &AttributeDefinition{
			Name:     "bad-struct",
			DataType: DataTypeStruct,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "bad-str", DataType: DataTypeString},
			},
		}
		_, err := DecodeStruct(bad, []byte{1, 2, 3})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "requires a Size hint")
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
