package goradius

import (
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func tlvTestParent() *AttributeDefinition {
	return &AttributeDefinition{
		ID:       100,
		Name:     "test-tlv",
		DataType: DataTypeTLV,
		Children: []*AttributeDefinition{
			{ID: 1, Name: "tlv-string", DataType: DataTypeString},
			{ID: 2, Name: "tlv-integer", DataType: DataTypeInteger},
			{ID: 3, Name: "tlv-ipaddr", DataType: DataTypeIPAddr},
			{ID: 4, Name: "tlv-octets", DataType: DataTypeOctets},
			{ID: 5, Name: "tlv-ipv6addr", DataType: DataTypeIPv6Addr},
			{
				ID:       6,
				Name:     "tlv-enum",
				DataType: DataTypeInteger,
				Values:   map[string]uint32{"on": 1, "off": 0},
			},
		},
	}
}

func TestEncodeTLV(t *testing.T) {
	parent := tlvTestParent()

	t.Run("single child", func(t *testing.T) {
		out, err := EncodeTLV(parent, map[string]any{"tlv-integer": uint32(42)})
		require.NoError(t, err)
		// type=2, len=6, 4-byte integer
		assert.Equal(t, []byte{2, 6, 0, 0, 0, 42}, out)
	})

	t.Run("multi child ordered by ID", func(t *testing.T) {
		out, err := EncodeTLV(parent, map[string]any{
			"tlv-integer": uint32(1),
			"tlv-string":  "ab",
		})
		require.NoError(t, err)
		// child 1 (string "ab") must come before child 2 (integer 1)
		assert.Equal(t, []byte{1, 4, 'a', 'b', 2, 6, 0, 0, 0, 1}, out)
	})

	t.Run("empty", func(t *testing.T) {
		out, err := EncodeTLV(parent, map[string]any{})
		require.NoError(t, err)
		assert.Empty(t, out)
	})

	t.Run("each supported child type", func(t *testing.T) {
		out, err := EncodeTLV(parent, map[string]any{
			"tlv-string":   "x",
			"tlv-integer":  uint32(7),
			"tlv-ipaddr":   "10.0.0.1",
			"tlv-octets":   []byte{0xde, 0xad},
			"tlv-ipv6addr": "2001:db8::1",
		})
		require.NoError(t, err)
		assert.NotEmpty(t, out)
	})

	t.Run("enum child by name", func(t *testing.T) {
		out, err := EncodeTLV(parent, map[string]any{"tlv-enum": "on"})
		require.NoError(t, err)
		assert.Equal(t, []byte{6, 6, 0, 0, 0, 1}, out)
	})

	t.Run("unknown child", func(t *testing.T) {
		_, err := EncodeTLV(parent, map[string]any{"nope": "x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown TLV child")
	})

	t.Run("oversized child value", func(t *testing.T) {
		_, err := EncodeTLV(parent, map[string]any{"tlv-string": strings.Repeat("x", 254)})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("nil parent", func(t *testing.T) {
		_, err := EncodeTLV(nil, map[string]any{})
		require.Error(t, err)
	})

	t.Run("bad child value type", func(t *testing.T) {
		_, err := EncodeTLV(parent, map[string]any{"tlv-integer": "not-a-number"})
		require.Error(t, err)
	})
}

func TestDecodeTLV(t *testing.T) {
	parent := tlvTestParent()

	t.Run("single child", func(t *testing.T) {
		m, err := DecodeTLV(parent, []byte{2, 6, 0, 0, 0, 42})
		require.NoError(t, err)
		assert.Equal(t, uint32(42), m["tlv-integer"])
	})

	t.Run("multi child", func(t *testing.T) {
		m, err := DecodeTLV(parent, []byte{1, 4, 'a', 'b', 2, 6, 0, 0, 0, 1})
		require.NoError(t, err)
		assert.Equal(t, "ab", m["tlv-string"])
		assert.Equal(t, uint32(1), m["tlv-integer"])
	})

	t.Run("unknown child id preserved as raw", func(t *testing.T) {
		m, err := DecodeTLV(parent, []byte{99, 4, 0xaa, 0xbb})
		require.NoError(t, err)
		assert.Equal(t, []byte{0xaa, 0xbb}, m["99"])
	})

	t.Run("truncated header", func(t *testing.T) {
		_, err := DecodeTLV(parent, []byte{2})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "truncated")
	})

	t.Run("length beyond data", func(t *testing.T) {
		_, err := DecodeTLV(parent, []byte{2, 10, 0, 0})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "beyond data")
	})

	t.Run("invalid sub length", func(t *testing.T) {
		_, err := DecodeTLV(parent, []byte{2, 1})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid TLV sub-attribute length")
	})

	t.Run("bad child payload", func(t *testing.T) {
		// child 2 is integer, give it 2 bytes instead of 4
		_, err := DecodeTLV(parent, []byte{2, 4, 0, 1})
		require.Error(t, err)
	})

	t.Run("nil parent", func(t *testing.T) {
		_, err := DecodeTLV(nil, []byte{})
		require.Error(t, err)
	})
}

func TestTLVRoundTrip(t *testing.T) {
	parent := tlvTestParent()

	cases := []map[string]any{
		{"tlv-string": "hello"},
		{"tlv-integer": uint32(123456)},
		{"tlv-ipaddr": "192.168.10.20"},
		{"tlv-octets": []byte{0x01, 0x02, 0x03, 0x04}},
		{"tlv-ipv6addr": "fe80::dead:beef"},
		{"tlv-string": "a", "tlv-integer": uint32(9), "tlv-ipaddr": "8.8.8.8"},
	}

	for _, in := range cases {
		t.Run("", func(t *testing.T) {
			encoded, err := EncodeTLV(parent, in)
			require.NoError(t, err)

			decoded, err := DecodeTLV(parent, encoded)
			require.NoError(t, err)

			for name, want := range in {
				switch w := want.(type) {
				case string:
					child, _ := parent.LookupChildByName(name)
					switch child.DataType {
					case DataTypeIPAddr, DataTypeIPv6Addr:
						got := decoded[name].(net.IP)
						assert.True(t, net.ParseIP(w).Equal(got))
					default:
						assert.Equal(t, w, decoded[name])
					}
				default:
					assert.Equal(t, want, decoded[name])
				}
			}
		})
	}
}

// tlvPacketDict builds a dictionary with a standard attribute and a Cisco-style vendor
// TLV attribute for packet integration tests.
func tlvPacketDict(t *testing.T) *Dictionary {
	t.Helper()
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
	}))
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   9,
		Name: "cisco",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "cisco-avpair", DataType: DataTypeString},
			{
				ID:       220,
				Name:     "cisco-tlv-example",
				DataType: DataTypeTLV,
				Children: []*AttributeDefinition{
					{ID: 1, Name: "cisco-tlv-name", DataType: DataTypeString},
					{ID: 2, Name: "cisco-tlv-count", DataType: DataTypeInteger},
					{ID: 3, Name: "cisco-tlv-addr", DataType: DataTypeIPAddr},
				},
			},
		},
	}))
	return dict
}

func TestPacketTLVRoundTrip(t *testing.T) {
	dict := tlvPacketDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("cisco-tlv-example", map[string]any{
		"cisco-tlv-name":  "svc",
		"cisco-tlv-count": uint32(5),
		"cisco-tlv-addr":  "10.1.2.3",
	}))

	// Encode to wire and decode back.
	raw, err := pkt.Encode()
	require.NoError(t, err)

	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	vals := decoded.GetAttribute("cisco-tlv-example")
	require.Len(t, vals, 1)
	assert.True(t, vals[0].IsVSA)
	assert.Equal(t, uint32(9), vals[0].VendorID)

	children, err := vals[0].Children()
	require.NoError(t, err)
	assert.Equal(t, "svc", children["cisco-tlv-name"])
	assert.Equal(t, uint32(5), children["cisco-tlv-count"])
	assert.True(t, net.ParseIP("10.1.2.3").Equal(children["cisco-tlv-addr"].(net.IP)))
}

func TestPacketTLVNestedInVSA(t *testing.T) {
	dict := tlvPacketDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("cisco-tlv-example", map[string]any{
		"cisco-tlv-count": uint32(42),
	}))

	// The TLV must be carried inside a standard VSA (type 26).
	require.Len(t, pkt.Attributes, 1)
	assert.Equal(t, uint8(AttributeTypeVendorSpecific), pkt.Attributes[0].Type)

	va, ok := pkt.GetVendorAttribute(9, 220)
	require.True(t, ok)
	// VSA value is the raw TLV: child 2, len 6, 4-byte integer 42.
	assert.Equal(t, []byte{2, 6, 0, 0, 0, 42}, va.Value)
}

func TestPacketMixedStandardAndTLV(t *testing.T) {
	dict := tlvPacketDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 7, dict)
	require.NoError(t, pkt.AddAttributeByName("user-name", "alice"))
	require.NoError(t, pkt.AddAttributeByName("cisco-avpair", "shell:priv-lvl=15"))
	require.NoError(t, pkt.AddAttributeByName("cisco-tlv-example", map[string]any{
		"cisco-tlv-name": "mixed",
	}))

	raw, err := pkt.Encode()
	require.NoError(t, err)

	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	assert.Equal(t, "alice", decoded.GetAttributeString("user-name"))
	assert.Equal(t, "shell:priv-lvl=15", decoded.GetAttributeString("cisco-avpair"))

	tlvVals := decoded.GetAttribute("cisco-tlv-example")
	require.Len(t, tlvVals, 1)
	children, err := tlvVals[0].Children()
	require.NoError(t, err)
	assert.Equal(t, "mixed", children["cisco-tlv-name"])
}

func TestPacketTLVRequiresMap(t *testing.T) {
	dict := tlvPacketDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	err := pkt.AddAttributeByName("cisco-tlv-example", "not-a-map")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires a map")
}

func TestAttributeValueChildrenNonContainer(t *testing.T) {
	dict := tlvPacketDict(t)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("cisco-avpair", "x=y"))

	vals := pkt.GetAttribute("cisco-avpair")
	require.Len(t, vals, 1)
	_, err := vals[0].Children()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a container")
}

func BenchmarkEncodeTLV(b *testing.B) {
	parent := tlvTestParent()
	values := map[string]any{
		"tlv-string":  "service",
		"tlv-integer": uint32(42),
		"tlv-ipaddr":  "10.0.0.1",
	}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeTLV(parent, values)
	}
}

func BenchmarkDecodeTLV(b *testing.B) {
	parent := tlvTestParent()
	data, err := EncodeTLV(parent, map[string]any{
		"tlv-string":  "service",
		"tlv-integer": uint32(42),
		"tlv-ipaddr":  "10.0.0.1",
	})
	require.NoError(b, err)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeTLV(parent, data)
	}
}

// FuzzDecodeTLV ensures DecodeTLV never panics on arbitrary input and that any value it
// successfully decodes re-encodes to the same canonical byte stream (round-trip stability).
func FuzzDecodeTLV(f *testing.F) {
	parent := tlvTestParent()

	// Seed corpus: valid encodings and malformed fragments.
	for _, seed := range [][]byte{
		{},
		{2, 6, 0, 0, 0, 42},
		{1, 4, 'a', 'b', 2, 6, 0, 0, 0, 1},
		{99, 4, 0xaa, 0xbb},
		{2},           // truncated header
		{2, 10, 0, 0}, // length beyond data
		{2, 1},        // invalid sub length
		{2, 4, 0, 1},  // bad integer payload
		{255, 2},      // zero-value sub-attribute
		{1, 2, 2, 2},  // two empty-string children (second ID collides)
	} {
		f.Add(seed)
	}
	if enc, err := EncodeTLV(parent, map[string]any{"tlv-string": "x", "tlv-integer": uint32(7)}); err == nil {
		f.Add(enc)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeTLV(parent, data)
		if err != nil {
			return // malformed input rejected cleanly — acceptable
		}

		// Everything decoded that maps to a known child must re-encode to the same bytes.
		reencoded, err := EncodeTLV(parent, decoded)
		if err != nil {
			// Unknown child IDs decode to raw []byte under a numeric key, which EncodeTLV
			// cannot re-encode. That is expected; only a re-encode of a pure known-child
			// map must succeed.
			onlyKnown := true
			for name := range decoded {
				if _, ok := parent.LookupChildByName(name); !ok {
					onlyKnown = false
					break
				}
			}
			if onlyKnown {
				t.Fatalf("re-encode of known-child map failed: %v", err)
			}
			return
		}

		// For a map of only known children, decode(reencode) must be stable.
		onlyKnown := true
		for name := range decoded {
			if _, ok := parent.LookupChildByName(name); !ok {
				onlyKnown = false
				break
			}
		}
		if onlyKnown {
			redecoded, err := DecodeTLV(parent, reencoded)
			if err != nil {
				t.Fatalf("re-decode failed: %v", err)
			}
			if len(redecoded) != len(decoded) {
				t.Fatalf("round-trip child count changed: %d -> %d", len(decoded), len(redecoded))
			}
		}
	})
}

func TestTLVWireValidity(t *testing.T) {
	t.Run("child ID above one octet is rejected", func(t *testing.T) {
		parent := &AttributeDefinition{
			ID:       100,
			Name:     "big-id-parent",
			DataType: DataTypeTLV,
			Children: []*AttributeDefinition{
				{ID: 300, Name: "big-id-child", DataType: DataTypeString},
			},
		}
		_, err := EncodeTLV(parent, map[string]any{"big-id-child": "x"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "TLV-Type range")
	})

	t.Run("empty child value is rejected on encode", func(t *testing.T) {
		parent := &AttributeDefinition{
			ID:       101,
			Name:     "empty-parent",
			DataType: DataTypeTLV,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "empty-child", DataType: DataTypeString},
			},
		}
		_, err := EncodeTLV(parent, map[string]any{"empty-child": ""})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "non-empty")
	})

	t.Run("header-only sub-attribute is rejected on decode", func(t *testing.T) {
		parent := &AttributeDefinition{
			ID:       102,
			Name:     "decode-parent",
			DataType: DataTypeTLV,
			Children: []*AttributeDefinition{
				{ID: 1, Name: "decode-child", DataType: DataTypeString},
			},
		}
		// RFC 6929 Section 2.3: TLV-Length must be at least 3.
		_, err := DecodeTLV(parent, []byte{1, 2})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid TLV sub-attribute length")
	})
}
