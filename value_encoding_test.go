package goradius

import (
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeInteger(t *testing.T) {
	tests := []uint32{0, 1, 123, 65535, 4294967295}

	for _, val := range tests {
		t.Run("", func(t *testing.T) {
			encoded := EncodeInteger(val)
			assert.Len(t, encoded, 4)

			decoded, err := DecodeInteger(encoded)
			assert.NoError(t, err)
			assert.Equal(t, val, decoded)
		})
	}
}

func TestEncodeDecodeIPAddr(t *testing.T) {
	tests := []string{
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
		"0.0.0.0",
		"255.255.255.255",
	}

	for _, ipStr := range tests {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)

			encoded, err := EncodeIPAddr(ip)
			require.NoError(t, err)
			assert.Len(t, encoded, 4)

			decoded, err := DecodeIPAddr(encoded)
			assert.NoError(t, err)
			assert.Equal(t, ipStr, decoded.String())
		})
	}
}

func TestEncodeDecodeIPv6Addr(t *testing.T) {
	tests := []string{
		"2001:db8::1",
		"fe80::1",
		"::1",
	}

	for _, ipStr := range tests {
		t.Run(ipStr, func(t *testing.T) {
			ip := net.ParseIP(ipStr)

			encoded, err := EncodeIPv6Addr(ip)
			require.NoError(t, err)
			assert.Len(t, encoded, 16)

			decoded, err := DecodeIPv6Addr(encoded)
			assert.NoError(t, err)
			assert.True(t, ip.Equal(decoded))
		})
	}
}

func TestEncodeDecodeDate(t *testing.T) {
	now := time.Now().Truncate(time.Second)

	encoded := EncodeDate(now)
	assert.Len(t, encoded, 4)

	decoded, err := DecodeDate(encoded)
	assert.NoError(t, err)
	assert.Equal(t, now.Unix(), decoded.Unix())
}

func TestEncodeDecodeString(t *testing.T) {
	tests := []string{
		"hello",
		"test@example.com",
		"",
		"long string with spaces and special chars !@#$%",
	}

	for _, str := range tests {
		t.Run(str, func(t *testing.T) {
			encoded := EncodeString(str)
			decoded := DecodeString(encoded)
			assert.Equal(t, str, decoded)
		})
	}
}

func TestEncodeValue(t *testing.T) {
	tests := []struct {
		name     string
		value    interface{}
		dataType DataType
		wantErr  bool
	}{
		{"string", "test", DataTypeString, false},
		{"integer-uint32", uint32(123), DataTypeInteger, false},
		{"integer-int", 123, DataTypeInteger, false},
		{"ipaddr-net.IP", net.ParseIP("192.168.1.1"), DataTypeIPAddr, false},
		{"ipaddr-string", "192.168.1.1", DataTypeIPAddr, false},
		{"octets", []byte{1, 2, 3}, DataTypeOctets, false},
		{"date", time.Now(), DataTypeDate, false},
		{"invalid-string", 123, DataTypeString, true},
		{"invalid-integer", "abc", DataTypeInteger, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := EncodeValue(tt.value, tt.dataType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, encoded)
			}
		})
	}
}

func TestDecodeOctets(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"single byte", []byte{0x42}},
		{"multiple bytes", []byte{0x01, 0x02, 0x03, 0x04}},
		{"binary data", []byte{0x00, 0xFF, 0xAA, 0x55}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DecodeOctets(tt.data)
			assert.Equal(t, tt.data, result)
		})
	}
}

func TestDecodeValue(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		data := []byte("hello")
		result, err := DecodeValue(data, DataTypeString)
		assert.NoError(t, err)
		assert.Equal(t, "hello", result)
	})

	t.Run("integer", func(t *testing.T) {
		data := EncodeInteger(42)
		result, err := DecodeValue(data, DataTypeInteger)
		assert.NoError(t, err)
		assert.Equal(t, uint32(42), result)
	})

	t.Run("ipaddr", func(t *testing.T) {
		ip := net.ParseIP("192.168.1.1")
		data, _ := EncodeIPAddr(ip)
		result, err := DecodeValue(data, DataTypeIPAddr)
		assert.NoError(t, err)
		assert.True(t, ip.Equal(result.(net.IP)))
	})

	t.Run("ipv6addr", func(t *testing.T) {
		ip := net.ParseIP("2001:db8::1")
		data, _ := EncodeIPv6Addr(ip)
		result, err := DecodeValue(data, DataTypeIPv6Addr)
		assert.NoError(t, err)
		assert.True(t, ip.Equal(result.(net.IP)))
	})

	t.Run("date", func(t *testing.T) {
		now := time.Date(2024, 11, 18, 12, 0, 0, 0, time.UTC)
		data := EncodeDate(now)
		result, err := DecodeValue(data, DataTypeDate)
		assert.NoError(t, err)
		assert.Equal(t, now.Unix(), result.(time.Time).Unix())
	})

	t.Run("octets", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03}
		result, err := DecodeValue(data, DataTypeOctets)
		assert.NoError(t, err)
		assert.Equal(t, data, result)
	})

	t.Run("abinary", func(t *testing.T) {
		data := []byte{0x01, 0x02, 0x03}
		result, err := DecodeValue(data, DataTypeABinary)
		assert.NoError(t, err)
		assert.Equal(t, data, result)
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := DecodeValue([]byte("test"), DataTypeTLV)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported data type")
	})
}

func TestEncodeValue_ErrorPaths(t *testing.T) {
	t.Run("ipaddr - invalid string", func(t *testing.T) {
		_, err := EncodeValue("not-an-ip", DataTypeIPAddr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IP address")
	})

	t.Run("ipaddr - wrong type", func(t *testing.T) {
		_, err := EncodeValue(123, DataTypeIPAddr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected net.IP or string")
	})

	t.Run("ipv6addr - invalid string", func(t *testing.T) {
		_, err := EncodeValue("not-an-ipv6", DataTypeIPv6Addr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid IPv6 address")
	})

	t.Run("ipv6addr - wrong type", func(t *testing.T) {
		_, err := EncodeValue(123, DataTypeIPv6Addr)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected net.IP or string")
	})

	t.Run("date - wrong type", func(t *testing.T) {
		_, err := EncodeValue("not-a-time", DataTypeDate)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected time.Time")
	})

	t.Run("octets - wrong type", func(t *testing.T) {
		_, err := EncodeValue("not-bytes", DataTypeOctets)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected []byte")
	})

	t.Run("abinary - wrong type", func(t *testing.T) {
		_, err := EncodeValue("not-bytes", DataTypeABinary)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expected []byte")
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := EncodeValue("test", DataTypeTLV)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported data type")
	})

	t.Run("integer - int32", func(t *testing.T) {
		encoded, err := EncodeValue(int32(42), DataTypeInteger)
		assert.NoError(t, err)
		decoded, _ := DecodeInteger(encoded)
		assert.Equal(t, uint32(42), decoded)
	})

	t.Run("ipv6addr - string", func(t *testing.T) {
		encoded, err := EncodeValue("::1", DataTypeIPv6Addr)
		assert.NoError(t, err)
		assert.Equal(t, 16, len(encoded))
	})
}

func TestEncodeIPAddr_ErrorPath(t *testing.T) {
	t.Run("IPv6 address", func(t *testing.T) {
		_, err := EncodeIPAddr(net.ParseIP("2001:db8::1"))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not an IPv4 address")
	})

	t.Run("nil IP", func(t *testing.T) {
		_, err := EncodeIPAddr(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not an IPv4 address")
	})
}

func TestEncodeIPv6Addr_ErrorPath(t *testing.T) {
	_, err := EncodeIPv6Addr(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not an IPv6 address")
}

func TestDecodeIPv6Addr_ErrorPath(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"too short", make([]byte, 15)},
		{"too long", make([]byte, 17)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := DecodeIPv6Addr(tt.data)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), "invalid IPv6 address length")
		})
	}
}

func TestDecodeDate_ErrorPath(t *testing.T) {
	_, err := DecodeDate([]byte{0x01, 0x02})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid integer length")
}

func TestJoinMultilineAttribute(t *testing.T) {
	t.Run("empty slice", func(t *testing.T) {
		result := JoinMultilineAttribute([]string{})
		assert.Equal(t, "", result)
	})

	t.Run("single value without marker", func(t *testing.T) {
		result := JoinMultilineAttribute([]string{"test value"})
		assert.Equal(t, "test value", result)
	})

	t.Run("single value with marker", func(t *testing.T) {
		result := JoinMultilineAttribute([]string{"test value<contd>"})
		assert.Equal(t, "test value", result)
	})

	t.Run("multiple values with markers", func(t *testing.T) {
		values := []string{
			"first part<contd>",
			"second part<contd>",
			"third part",
		}
		result := JoinMultilineAttribute(values)
		assert.Equal(t, "first partsecond partthird part", result)
	})

	t.Run("multiple values mixed markers", func(t *testing.T) {
		values := []string{
			"first<contd>",
			"second",
			"third<contd>",
		}
		result := JoinMultilineAttribute(values)
		assert.Equal(t, "firstsecondthird", result)
	})

	t.Run("juniper style multi-line", func(t *testing.T) {
		values := []string{
			"permit source-address 192.168.1.0/24<contd>",
			" destination-address 10.0.0.0/8<contd>",
			" application any",
		}
		result := JoinMultilineAttribute(values)
		expected := "permit source-address 192.168.1.0/24 destination-address 10.0.0.0/8 application any"
		assert.Equal(t, expected, result)
	})

	t.Run("production juniper user permissions", func(t *testing.T) {
		// Real production value from Juniper-User-Permissions attribute
		permissions := "access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session-mirroring-control unified-edge unified-edge-control"

		// This value is 526 characters, which exceeds the 247-byte VSA limit
		assert.Equal(t, 526, len(permissions))

		// Split into chunks suitable for VSA
		chunks := SplitMultilineAttribute(permissions, 247)

		// Should be split into at least 3 chunks (526 bytes / ~240 bytes per chunk)
		assert.GreaterOrEqual(t, len(chunks), 3)

		// All chunks except last should have continuation marker
		for i := 0; i < len(chunks)-1; i++ {
			assert.True(t, strings.HasSuffix(chunks[i], "<contd>"))
			assert.LessOrEqual(t, len(chunks[i]), 247)
		}

		// Last chunk should not have continuation marker
		assert.False(t, strings.HasSuffix(chunks[len(chunks)-1], "<contd>"))

		// Join back and verify we get the original value
		rejoined := JoinMultilineAttribute(chunks)
		assert.Equal(t, permissions, rejoined)
	})
}

func TestSplitMultilineAttribute(t *testing.T) {
	t.Run("empty string", func(t *testing.T) {
		chunks := SplitMultilineAttribute("", 247)
		assert.Equal(t, []string{""}, chunks)
	})

	t.Run("short string fits in one chunk", func(t *testing.T) {
		value := "short value"
		chunks := SplitMultilineAttribute(value, 247)
		assert.Equal(t, []string{"short value"}, chunks)
	})

	t.Run("exactly max length", func(t *testing.T) {
		value := strings.Repeat("x", 247)
		chunks := SplitMultilineAttribute(value, 247)
		assert.Equal(t, []string{value}, chunks)
	})

	t.Run("split into two chunks", func(t *testing.T) {
		value := strings.Repeat("x", 300)
		chunks := SplitMultilineAttribute(value, 247)

		assert.Len(t, chunks, 2)
		assert.True(t, strings.HasSuffix(chunks[0], "<contd>"))
		assert.False(t, strings.HasSuffix(chunks[1], "<contd>"))

		joined := JoinMultilineAttribute(chunks)
		assert.Equal(t, value, joined)
	})

	t.Run("split into multiple chunks", func(t *testing.T) {
		value := strings.Repeat("x", 1000)
		chunks := SplitMultilineAttribute(value, 247)

		assert.True(t, len(chunks) >= 3)

		for i := 0; i < len(chunks)-1; i++ {
			assert.True(t, strings.HasSuffix(chunks[i], "<contd>"))
			assert.LessOrEqual(t, len(chunks[i]), 247)
		}

		assert.False(t, strings.HasSuffix(chunks[len(chunks)-1], "<contd>"))

		joined := JoinMultilineAttribute(chunks)
		assert.Equal(t, value, joined)
	})

	t.Run("split with standard attribute max length", func(t *testing.T) {
		value := strings.Repeat("y", 500)
		chunks := SplitMultilineAttribute(value, 253)

		for i := 0; i < len(chunks)-1; i++ {
			assert.LessOrEqual(t, len(chunks[i]), 253)
		}

		joined := JoinMultilineAttribute(chunks)
		assert.Equal(t, value, joined)
	})

	t.Run("roundtrip with 4000 characters", func(t *testing.T) {
		value := strings.Repeat("ABCDEFGHIJ", 400)
		assert.Equal(t, 4000, len(value))

		chunks := SplitMultilineAttribute(value, 247)
		assert.True(t, len(chunks) >= 16)

		joined := JoinMultilineAttribute(chunks)
		assert.Equal(t, value, joined)
	})

	t.Run("small max length", func(t *testing.T) {
		value := "test value that is longer than ten characters"
		chunks := SplitMultilineAttribute(value, 10)

		for i := 0; i < len(chunks)-1; i++ {
			assert.LessOrEqual(t, len(chunks[i]), 10)
		}

		joined := JoinMultilineAttribute(chunks)
		assert.Equal(t, value, joined)
	})

	t.Run("production juniper permissions split and join", func(t *testing.T) {
		// Real production value from Juniper-User-Permissions attribute
		permissions := "access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session-mirroring-control unified-edge unified-edge-control"

		// Split for VSA (247 bytes max)
		chunks := SplitMultilineAttribute(permissions, 247)

		// Verify chunk count and sizes - 526 chars should fit in 3 chunks
		assert.GreaterOrEqual(t, len(chunks), 3)
		assert.LessOrEqual(t, len(chunks), 4)

		// Verify each chunk respects the limit
		for i, chunk := range chunks {
			assert.LessOrEqual(t, len(chunk), 247, "chunk %d exceeds limit", i)
		}

		// Verify roundtrip
		rejoined := JoinMultilineAttribute(chunks)
		assert.Equal(t, permissions, rejoined)
		assert.Equal(t, 526, len(rejoined))
	})
}

func TestEncodeDecodeIPv6Prefix(t *testing.T) {
	t.Run("round trip /32", func(t *testing.T) {
		_, ipnet, err := net.ParseCIDR("2001:db8::/32")
		require.NoError(t, err)

		encoded, err := EncodeIPv6Prefix(ipnet)
		require.NoError(t, err)
		// RFC 3162 Section 2.3: reserved(0) + prefix-length + 4 prefix octets
		assert.Equal(t, []byte{0, 32, 0x20, 0x01, 0x0d, 0xb8}, encoded)

		decoded, err := DecodeIPv6Prefix(encoded)
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::/32", decoded.String())
	})

	t.Run("zero-length prefix", func(t *testing.T) {
		_, ipnet, err := net.ParseCIDR("::/0")
		require.NoError(t, err)

		encoded, err := EncodeIPv6Prefix(ipnet)
		require.NoError(t, err)
		assert.Equal(t, []byte{0, 0}, encoded)

		decoded, err := DecodeIPv6Prefix(encoded)
		require.NoError(t, err)
		assert.Equal(t, "::/0", decoded.String())
	})

	t.Run("full /128", func(t *testing.T) {
		_, ipnet, err := net.ParseCIDR("2001:db8::1/128")
		require.NoError(t, err)

		encoded, err := EncodeIPv6Prefix(ipnet)
		require.NoError(t, err)
		require.Len(t, encoded, 18)

		decoded, err := DecodeIPv6Prefix(encoded)
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::1/128", decoded.String())
	})

	t.Run("nil prefix", func(t *testing.T) {
		_, err := EncodeIPv6Prefix(nil)
		require.Error(t, err)
	})

	t.Run("ipv4 prefix rejected", func(t *testing.T) {
		_, ipnet, err := net.ParseCIDR("10.0.0.0/8")
		require.NoError(t, err)
		_, err = EncodeIPv6Prefix(ipnet)
		require.Error(t, err)
	})

	t.Run("decode too short", func(t *testing.T) {
		_, err := DecodeIPv6Prefix([]byte{0})
		require.Error(t, err)
	})

	t.Run("decode prefix length over 128", func(t *testing.T) {
		_, err := DecodeIPv6Prefix([]byte{0, 129})
		require.Error(t, err)
	})

	t.Run("decode prefix field too short for prefix length", func(t *testing.T) {
		_, err := DecodeIPv6Prefix([]byte{0, 64, 0x20})
		require.Error(t, err)
	})

	t.Run("decode too long", func(t *testing.T) {
		_, err := DecodeIPv6Prefix(make([]byte, 19))
		require.Error(t, err)
	})
}

func TestEncodeDecodeIfID(t *testing.T) {
	ifid := []byte{0, 0, 0, 0, 0, 0, 0, 1}

	t.Run("round trip", func(t *testing.T) {
		encoded, err := EncodeIfID(ifid)
		require.NoError(t, err)
		assert.Equal(t, ifid, encoded)

		decoded, err := DecodeIfID(encoded)
		require.NoError(t, err)
		assert.Equal(t, ifid, decoded)
	})

	t.Run("wrong length rejected", func(t *testing.T) {
		_, err := EncodeIfID([]byte{1, 2, 3})
		require.Error(t, err)
		_, err = DecodeIfID([]byte{1, 2, 3})
		require.Error(t, err)
	})
}

func TestEncodeDecodeValueRFC3162(t *testing.T) {
	t.Run("ipv6prefix via EncodeValue string", func(t *testing.T) {
		encoded, err := EncodeValue("2001:db8::/32", DataTypeIPv6Prefix)
		require.NoError(t, err)

		decoded, err := DecodeValue(encoded, DataTypeIPv6Prefix)
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::/32", decoded.(*net.IPNet).String())
	})

	t.Run("ipv6prefix via EncodeValue IPNet", func(t *testing.T) {
		_, ipnet, err := net.ParseCIDR("fd00::/8")
		require.NoError(t, err)
		encoded, err := EncodeValue(ipnet, DataTypeIPv6Prefix)
		require.NoError(t, err)
		assert.Equal(t, []byte{0, 8, 0xfd}, encoded)
	})

	t.Run("ipv6prefix invalid string", func(t *testing.T) {
		_, err := EncodeValue("not-a-cidr", DataTypeIPv6Prefix)
		require.Error(t, err)
	})

	t.Run("ifid via EncodeValue", func(t *testing.T) {
		ifid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
		encoded, err := EncodeValue(ifid, DataTypeIfID)
		require.NoError(t, err)

		decoded, err := DecodeValue(encoded, DataTypeIfID)
		require.NoError(t, err)
		assert.Equal(t, ifid, decoded)
	})

	t.Run("ifid wrong type", func(t *testing.T) {
		_, err := EncodeValue("string", DataTypeIfID)
		require.Error(t, err)
	})
}

// FuzzDecodeIPv6Prefix ensures the prefix decoder never panics and that decoded
// prefixes re-encode and decode to the same prefix.
func FuzzDecodeIPv6Prefix(f *testing.F) {
	f.Add([]byte{0, 32, 0x20, 0x01, 0x0d, 0xb8})
	f.Add([]byte{0, 0})
	f.Add([]byte{0})
	f.Add([]byte{0, 129})
	f.Add([]byte{0, 64, 0x20})
	// Regression: prefix bits beyond the prefix length must be masked on decode
	f.Add([]byte{0x30, 0x00, 0x30})

	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := DecodeIPv6Prefix(data)
		if err != nil {
			return
		}

		reencoded, err := EncodeIPv6Prefix(decoded)
		if err != nil {
			t.Fatalf("re-encode of decoded prefix failed: %v", err)
		}
		redecoded, err := DecodeIPv6Prefix(reencoded)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if decoded.String() != redecoded.String() {
			t.Fatalf("prefix round trip mismatch: %s != %s", decoded, redecoded)
		}
	})
}

func BenchmarkEncodeIPv6Prefix(b *testing.B) {
	_, ipnet, _ := net.ParseCIDR("2001:db8::/32")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeIPv6Prefix(ipnet)
	}
}

func BenchmarkDecodeIPv6Prefix(b *testing.B) {
	data := []byte{0, 32, 0x20, 0x01, 0x0d, 0xb8}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeIPv6Prefix(data)
	}
}

// FuzzDecodeValue ensures the scalar value decoder never panics for any data type
// selector and arbitrary payload bytes.
func FuzzDecodeValue(f *testing.F) {
	dataTypes := []DataType{
		DataTypeString,
		DataTypeInteger,
		DataTypeIPAddr,
		DataTypeIPv6Addr,
		DataTypeIPv6Prefix,
		DataTypeIfID,
		DataTypeDate,
		DataTypeOctets,
		DataTypeABinary,
		DataTypeTLV, // unsupported by DecodeValue; must error, not panic
	}

	f.Add(uint8(0), []byte("hello"))
	f.Add(uint8(1), []byte{0, 0, 0, 42})
	f.Add(uint8(2), []byte{10, 0, 0, 1})
	f.Add(uint8(7), []byte{1, 2, 3})

	f.Fuzz(func(_ *testing.T, typeIdx uint8, data []byte) {
		dataType := dataTypes[int(typeIdx)%len(dataTypes)]
		_, _ = DecodeValue(data, dataType) // must not panic
	})
}

func BenchmarkEncodeString(b *testing.B) {
	str := "testuser"
	b.ReportAllocs()
	for b.Loop() {
		_ = EncodeString(str)
	}
}

func BenchmarkDecodeString(b *testing.B) {
	data := []byte("testuser")
	b.ReportAllocs()
	for b.Loop() {
		_ = DecodeString(data)
	}
}

func BenchmarkEncodeInteger(b *testing.B) {
	val := uint32(3600)
	b.ReportAllocs()
	for b.Loop() {
		_ = EncodeInteger(val)
	}
}

func BenchmarkDecodeInteger(b *testing.B) {
	data := EncodeInteger(3600)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeInteger(data)
	}
}

func BenchmarkEncodeIPAddr(b *testing.B) {
	ip := net.ParseIP("192.168.1.1")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeIPAddr(ip)
	}
}

func BenchmarkDecodeIPAddr(b *testing.B) {
	data := []byte{192, 168, 1, 1}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeIPAddr(data)
	}
}

func BenchmarkEncodeIPv6Addr(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeIPv6Addr(ip)
	}
}

func BenchmarkDecodeIPv6Addr(b *testing.B) {
	ip := net.ParseIP("2001:db8::1")
	data, _ := EncodeIPv6Addr(ip)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeIPv6Addr(data)
	}
}

func BenchmarkEncodeDate(b *testing.B) {
	now := time.Now()
	b.ReportAllocs()
	for b.Loop() {
		_ = EncodeDate(now)
	}
}

func BenchmarkDecodeDate(b *testing.B) {
	data := EncodeDate(time.Now())
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeDate(data)
	}
}

func BenchmarkEncodeValueString(b *testing.B) {
	val := "testuser"
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeValue(val, DataTypeString)
	}
}

func BenchmarkEncodeValueInteger(b *testing.B) {
	val := uint32(3600)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeValue(val, DataTypeInteger)
	}
}

func BenchmarkEncodeValueIPAddr(b *testing.B) {
	val := "192.168.1.1"
	b.ReportAllocs()
	for b.Loop() {
		_, _ = EncodeValue(val, DataTypeIPAddr)
	}
}

func BenchmarkDecodeValueString(b *testing.B) {
	data := []byte("testuser")
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeValue(data, DataTypeString)
	}
}

func BenchmarkDecodeValueInteger(b *testing.B) {
	data := EncodeInteger(3600)
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeValue(data, DataTypeInteger)
	}
}

func BenchmarkDecodeValueIPAddr(b *testing.B) {
	data := []byte{192, 168, 1, 1}
	b.ReportAllocs()
	for b.Loop() {
		_, _ = DecodeValue(data, DataTypeIPAddr)
	}
}
