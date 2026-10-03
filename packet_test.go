package goradius

import (
	"crypto/hmac"
	"crypto/md5"
	"encoding/hex"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	require.NoError(t, err)
	return data
}

func TestNewPacket(t *testing.T) {
	tests := []struct {
		name       string
		code       Code
		identifier uint8
	}{
		{"Access-Request", CodeAccessRequest, 1},
		{"Access-Accept", CodeAccessAccept, 2},
		{"Accounting-Request", CodeAccountingRequest, 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := NewPacket(tt.code, tt.identifier)
			assert.Equal(t, tt.code, pkt.Code)
			assert.Equal(t, tt.identifier, pkt.Identifier)
			assert.Equal(t, uint16(PacketHeaderLength), pkt.Length)
			assert.Empty(t, pkt.Attributes)
		})
	}
}

func TestPacketAddAttribute(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)

	attr := NewAttribute(1, []byte("testuser"))
	pkt.AddAttribute(attr)

	assert.Len(t, pkt.Attributes, 1)
	assert.Equal(t, uint8(1), pkt.Attributes[0].Type)
	assert.Equal(t, []byte("testuser"), pkt.Attributes[0].Value)
	assert.Equal(t, PacketHeaderLength+uint16(attr.Length), pkt.Length)
}

func TestPacketGetAttribute(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)

	attr := NewAttribute(1, []byte("testuser"))
	pkt.AddAttribute(attr)

	attrs := pkt.GetAttributes(1)
	assert.Len(t, attrs, 1)
	assert.Equal(t, []byte("testuser"), attrs[0].Value)

	attrs = pkt.GetAttributes(99)
	assert.Empty(t, attrs)
}

func TestPacketGetAttributes(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)

	pkt.AddAttribute(NewAttribute(1, []byte("user1")))
	pkt.AddAttribute(NewAttribute(1, []byte("user2")))
	pkt.AddAttribute(NewAttribute(2, []byte("other")))

	attrs := pkt.GetAttributes(1)
	assert.Len(t, attrs, 2)
	assert.Equal(t, []byte("user1"), attrs[0].Value)
	assert.Equal(t, []byte("user2"), attrs[1].Value)

	attrs = pkt.GetAttributes(99)
	assert.Empty(t, attrs)
}

func TestPacketRemoveAttribute(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)

	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
	pkt.AddAttribute(NewAttribute(2, []byte("testpass")))

	removed := pkt.RemoveAttribute(1)
	assert.True(t, removed)
	assert.Len(t, pkt.Attributes, 1)

	removed = pkt.RemoveAttribute(99)
	assert.False(t, removed)
}

func TestPacketRemoveAttributes(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)

	pkt.AddAttribute(NewAttribute(1, []byte("user1")))
	pkt.AddAttribute(NewAttribute(1, []byte("user2")))
	pkt.AddAttribute(NewAttribute(2, []byte("pass")))

	count := pkt.RemoveAttributes(1)
	assert.Equal(t, 2, count)
	assert.Len(t, pkt.Attributes, 1)

	count = pkt.RemoveAttributes(99)
	assert.Equal(t, 0, count)
}

func TestPacketIsValid(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *Packet
		wantErr bool
	}{
		{
			name: "valid packet",
			setup: func() *Packet {
				return NewPacket(CodeAccessRequest, 1)
			},
			wantErr: false,
		},
		{
			name: "invalid code",
			setup: func() *Packet {
				pkt := NewPacket(CodeAccessRequest, 1)
				pkt.Code = 99
				return pkt
			},
			wantErr: true,
		},
		{
			name: "packet too short",
			setup: func() *Packet {
				pkt := NewPacket(CodeAccessRequest, 1)
				pkt.Length = 10
				return pkt
			},
			wantErr: true,
		},
		{
			name: "packet too long",
			setup: func() *Packet {
				pkt := NewPacket(CodeAccessRequest, 1)
				pkt.Length = 5000
				return pkt
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := tt.setup()
			err := pkt.IsValid()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPacketAuthenticatorCalculation(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

	secret := []byte("testing123")

	// Calculate request authenticator
	reqAuth := pkt.CalculateRequestAuthenticator(secret)
	assert.Len(t, reqAuth, AuthenticatorLength)

	// Create response
	resp := NewPacket(CodeAccessAccept, 1)
	resp.AddAttribute(NewAttribute(18, []byte("Welcome")))

	// Calculate response authenticator
	respAuth := resp.CalculateResponseAuthenticator(secret, reqAuth)
	assert.Len(t, respAuth, AuthenticatorLength)

	// Response auth should be different from request auth
	assert.NotEqual(t, reqAuth, respAuth)
}

func TestPacketWithDictionary(t *testing.T) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       1,
			Name:     "user-name",
			DataType: DataTypeString,
		},
		{
			ID:       8,
			Name:     "framed-ip-address",
			DataType: DataTypeIPAddr,
		},
	})

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	assert.NotNil(t, pkt.Dict)

	pkt.AddAttributeByName("user-name", "testuser")
	pkt.AddAttributeByName("framed-ip-address", "192.0.2.10")

	assert.Len(t, pkt.Attributes, 2)

	userAttrs := pkt.GetAttributes(1)
	assert.Len(t, userAttrs, 1)
	assert.Equal(t, []byte("testuser"), userAttrs[0].Value)

	ipAttrs := pkt.GetAttributes(8)
	assert.Len(t, ipAttrs, 1)
	ip, err := DecodeIPAddr(ipAttrs[0].Value)
	assert.NoError(t, err)
	assert.Equal(t, "192.0.2.10", ip.String())
}

func TestPacketVendorAttributes(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)

	va := NewVendorAttribute(4874, 13, []byte("8.8.8.8"))
	pkt.AddVendorAttribute(va)

	assert.Len(t, pkt.Attributes, 1)
	assert.Equal(t, uint8(26), pkt.Attributes[0].Type) // VSA type

	foundVA, ok := pkt.GetVendorAttribute(4874, 13)
	assert.True(t, ok)
	assert.Equal(t, uint32(4874), foundVA.VendorID)
	assert.Equal(t, uint32(13), foundVA.VendorType)
	assert.Equal(t, []byte("8.8.8.8"), foundVA.Value)
}

func TestPacketTaggedVendorAttributes(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)

	va := NewTaggedVendorAttribute(4874, 1, 3, []byte("test-service"))
	pkt.AddVendorAttribute(va)

	foundVA, ok := pkt.GetVendorAttribute(4874, 1)
	assert.True(t, ok)
	assert.Equal(t, uint8(3), foundVA.Tag)
	assert.Equal(t, []byte("test-service"), foundVA.GetValue())
}

func TestPacketString(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 42)
	pkt.AddAttribute(NewAttribute(1, []byte("test")))

	str := pkt.String()
	assert.Contains(t, str, "Access-Request")
	assert.Contains(t, str, "ID=42")
	assert.Contains(t, str, "Attributes=1")
}

func TestPacketListAttributes(t *testing.T) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
		{ID: 4, Name: "nas-ip-address", DataType: DataTypeIPAddr},
		{ID: 8, Name: "framed-ip-address", DataType: DataTypeIPAddr},
	})
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 4, Name: "erx-primary-dns", DataType: DataTypeIPAddr},
			{ID: 138, Name: "erx-dhcp-mac-addr", DataType: DataTypeString},
		},
	})

	t.Run("no dictionary", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		result := pkt.ListAttributes()
		assert.Empty(t, result)
	})

	t.Run("with dictionary - standard attributes", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "user-name")
		assert.Contains(t, result, "nas-ip-address")
	})

	t.Run("with dictionary - duplicate attributes", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser1")))
		pkt.AddAttribute(NewAttribute(1, []byte("testuser2")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "user-name")
		assert.Contains(t, result, "nas-ip-address")
	})

	t.Run("with dictionary - vendor attributes", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("aa:bb:cc:dd:ee:ff")))

		result := pkt.ListAttributes()
		assert.Len(t, result, 3)
		assert.Contains(t, result, "user-name")
		assert.Contains(t, result, "erx-primary-dns")
		assert.Contains(t, result, "erx-dhcp-mac-addr")
	})

	t.Run("with dictionary - unknown attributes skipped", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddAttribute(NewAttribute(99, []byte("unknown")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "user-name")
		assert.Contains(t, result, "nas-ip-address")
		assert.NotContains(t, result, "unknown")
	})

	t.Run("with dictionary - unknown vendor attributes skipped", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))
		pkt.AddVendorAttribute(NewVendorAttribute(9999, 1, []byte("unknown vendor")))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "user-name")
		assert.Contains(t, result, "erx-primary-dns")
	})

	t.Run("empty packet", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)

		result := pkt.ListAttributes()
		assert.Empty(t, result)
	})
}

func TestPacketGetAttributeByName(t *testing.T) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
		{ID: 4, Name: "nas-ip-address", DataType: DataTypeIPAddr},
		{ID: 27, Name: "session-timeout", DataType: DataTypeInteger},
	})
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 4, Name: "erx-primary-dns", DataType: DataTypeIPAddr},
			{ID: 138, Name: "erx-dhcp-mac-addr", DataType: DataTypeString},
		},
	})

	t.Run("no dictionary", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		result := pkt.GetAttribute("user-name")
		assert.Empty(t, result)
	})

	t.Run("standard attribute - single value", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		values := pkt.GetAttribute("user-name")
		assert.Len(t, values, 1)
		assert.Equal(t, "user-name", values[0].Name)
		assert.Equal(t, uint8(1), values[0].Type)
		assert.Equal(t, DataTypeString, values[0].DataType)
		assert.Equal(t, []byte("testuser"), values[0].Value)
		assert.False(t, values[0].IsVSA)
	})

	t.Run("standard attribute - multiple values", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("user1")))
		pkt.AddAttribute(NewAttribute(1, []byte("user2")))
		pkt.AddAttribute(NewAttribute(1, []byte("user3")))

		values := pkt.GetAttribute("user-name")
		assert.Len(t, values, 3)
		assert.Equal(t, []byte("user1"), values[0].Value)
		assert.Equal(t, []byte("user2"), values[1].Value)
		assert.Equal(t, []byte("user3"), values[2].Value)
	})

	t.Run("VSA attribute - single value", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))

		values := pkt.GetAttribute("erx-primary-dns")
		assert.Len(t, values, 1)
		assert.Equal(t, "erx-primary-dns", values[0].Name)
		assert.Equal(t, uint8(26), values[0].Type)
		assert.Equal(t, DataTypeIPAddr, values[0].DataType)
		assert.Equal(t, []byte{192, 0, 2, 1}, values[0].Value)
		assert.True(t, values[0].IsVSA)
		assert.Equal(t, uint32(4874), values[0].VendorID)
		assert.Equal(t, uint32(4), values[0].VendorType)
	})

	t.Run("VSA attribute - multiple values", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("aa:bb:cc:dd:ee:ff")))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("11:22:33:44:55:66")))

		values := pkt.GetAttribute("erx-dhcp-mac-addr")
		assert.Len(t, values, 2)
		assert.Equal(t, []byte("aa:bb:cc:dd:ee:ff"), values[0].Value)
		assert.Equal(t, []byte("11:22:33:44:55:66"), values[1].Value)
		assert.True(t, values[0].IsVSA)
		assert.True(t, values[1].IsVSA)
	})

	t.Run("attribute not found", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		values := pkt.GetAttribute("NonExistent")
		assert.Empty(t, values)
	})

	t.Run("attribute not in dictionary", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(99, []byte("unknown")))

		values := pkt.GetAttribute("unknown-attribute")
		assert.Empty(t, values)
	})

	t.Run("mixed attributes", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))

		userValues := pkt.GetAttribute("user-name")
		assert.Len(t, userValues, 1)
		assert.Equal(t, "user-name", userValues[0].Name)

		nasValues := pkt.GetAttribute("nas-ip-address")
		assert.Len(t, nasValues, 1)
		assert.Equal(t, "nas-ip-address", nasValues[0].Name)

		dnsValues := pkt.GetAttribute("erx-primary-dns")
		assert.Len(t, dnsValues, 1)
		assert.Equal(t, "erx-primary-dns", dnsValues[0].Name)
		assert.True(t, dnsValues[0].IsVSA)
	})
}

func TestAttributeValueString(t *testing.T) {
	t.Run("string type", func(t *testing.T) {
		av := AttributeValue{
			DataType: DataTypeString,
			Value:    []byte("testuser"),
		}
		assert.Equal(t, "testuser", av.String())
	})

	t.Run("integer type", func(t *testing.T) {
		av := AttributeValue{
			DataType: DataTypeInteger,
			Value:    EncodeInteger(3600),
		}
		assert.Equal(t, "3600", av.String())
	})

	t.Run("ipaddr type", func(t *testing.T) {
		av := AttributeValue{
			DataType: DataTypeIPAddr,
			Value:    []byte{192, 168, 1, 1},
		}
		assert.Equal(t, "192.168.1.1", av.String())
	})

	t.Run("ipv6addr type", func(t *testing.T) {
		ip := net.ParseIP("2001:db8::1")
		encoded, _ := EncodeIPv6Addr(ip)
		av := AttributeValue{
			DataType: DataTypeIPv6Addr,
			Value:    encoded,
		}
		assert.Equal(t, "2001:db8::1", av.String())
	})

	t.Run("date type", func(t *testing.T) {
		now := time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC)
		av := AttributeValue{
			DataType: DataTypeDate,
			Value:    EncodeDate(now),
		}
		// DecodeDate returns local time, so convert expected time to local
		expected := time.Unix(now.Unix(), 0).Format(time.RFC3339)
		assert.Equal(t, expected, av.String())
	})

	t.Run("octets type", func(t *testing.T) {
		av := AttributeValue{
			DataType: DataTypeOctets,
			Value:    []byte{0x1a, 0x2b, 0x3c, 0x4d},
		}
		assert.Equal(t, "0x1a2b3c4d", av.String())
	})

	t.Run("unknown type", func(t *testing.T) {
		av := AttributeValue{
			DataType: DataType("unknown"),
			Value:    []byte{0xaa, 0xbb, 0xcc},
		}
		assert.Equal(t, "0xaabbcc", av.String())
	})

	t.Run("invalid integer", func(t *testing.T) {
		av := AttributeValue{
			DataType: DataTypeInteger,
			Value:    []byte{0x01}, // Invalid length for integer
		}
		assert.Equal(t, "0x01", av.String())
	})

	t.Run("invalid ipaddr", func(t *testing.T) {
		av := AttributeValue{
			DataType: DataTypeIPAddr,
			Value:    []byte{0x01, 0x02}, // Invalid length for IP
		}
		assert.Equal(t, "0x0102", av.String())
	})
}

func TestArrayAttributeHandling(t *testing.T) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 18, Name: "reply-message", DataType: DataTypeString},
	})

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)

	t.Run("single value as array", func(t *testing.T) {
		// Single value should still work
		pkt.AddAttributeByName("reply-message", "Single message")

		attrs := pkt.GetAttribute("reply-message")
		assert.Len(t, attrs, 1)
		assert.Equal(t, "Single message", attrs[0].String())
	})

	t.Run("slice of strings", func(t *testing.T) {
		pkt2 := NewPacketWithDictionary(CodeAccessAccept, 2, dict)

		// Pass a slice of strings
		messages := []string{"First message", "Second message", "Third message"}
		pkt2.AddAttributeByName("reply-message", messages)

		attrs := pkt2.GetAttribute("reply-message")
		assert.Len(t, attrs, 3)
		assert.Equal(t, "First message", attrs[0].String())
		assert.Equal(t, "Second message", attrs[1].String())
		assert.Equal(t, "Third message", attrs[2].String())
	})

	t.Run("slice of interfaces", func(t *testing.T) {
		pkt3 := NewPacketWithDictionary(CodeAccessAccept, 3, dict)

		// Pass a slice of interface{}
		messages := []interface{}{"Message one", "Message two"}
		pkt3.AddAttributeByName("reply-message", messages)

		attrs := pkt3.GetAttribute("reply-message")
		assert.Len(t, attrs, 2)
		assert.Equal(t, "Message one", attrs[0].String())
		assert.Equal(t, "Message two", attrs[1].String())
	})
}

func TestVendorArrayAttributeHandling(t *testing.T) {
	vendor := &VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "erx-service-activate", DataType: DataTypeString, HasTag: true},
			{ID: 4, Name: "erx-primary-dns", DataType: DataTypeIPAddr, HasTag: false},
		},
	}

	dict := NewDictionary()
	require.NoError(t, dict.AddVendor(vendor))

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)

	t.Run("single vendor value with tag", func(t *testing.T) {
		pkt.AddAttributeByName("erx-service-activate:1", "service1")

		attrs := pkt.GetAttribute("erx-service-activate")
		assert.Len(t, attrs, 1)
		assert.Equal(t, uint8(1), attrs[0].Tag)
		assert.Equal(t, "service1", attrs[0].String())
	})

	t.Run("multiple vendor values with tag", func(t *testing.T) {
		pkt2 := NewPacketWithDictionary(CodeAccessAccept, 2, dict)

		services := []string{"service-a", "service-b", "service-c"}
		pkt2.AddAttributeByName("erx-service-activate:1", services)

		attrs := pkt2.GetAttribute("erx-service-activate")
		assert.Len(t, attrs, 3)
		assert.Equal(t, uint8(1), attrs[0].Tag)
		assert.Equal(t, "service-a", attrs[0].String())
		assert.Equal(t, uint8(1), attrs[1].Tag)
		assert.Equal(t, "service-b", attrs[1].String())
		assert.Equal(t, uint8(1), attrs[2].Tag)
		assert.Equal(t, "service-c", attrs[2].String())
	})

	t.Run("non-tagged vendor attributes with IP addresses", func(t *testing.T) {
		pkt3 := NewPacketWithDictionary(CodeAccessAccept, 3, dict)

		dnsServers := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"}
		pkt3.AddAttributeByName("erx-primary-dns", dnsServers)

		attrs := pkt3.GetAttribute("erx-primary-dns")
		assert.Len(t, attrs, 3)
		assert.Equal(t, uint8(0), attrs[0].Tag) // No tag
		assert.Equal(t, "8.8.8.8", attrs[0].String())
		assert.Equal(t, uint8(0), attrs[1].Tag)
		assert.Equal(t, "8.8.4.4", attrs[1].String())
		assert.Equal(t, uint8(0), attrs[2].Tag)
		assert.Equal(t, "1.1.1.1", attrs[2].String())
	})
}

func TestRemoveAttributeByName(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	t.Run("remove standard attribute", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)

		// Add multiple Reply-Message attributes
		pkt.AddAttributeByName("reply-message", "Message 1")
		pkt.AddAttributeByName("reply-message", "Message 2")
		pkt.AddAttributeByName("reply-message", "Message 3")
		pkt.AddAttributeByName("session-timeout", 3600)

		// Verify all were added
		msgs := pkt.GetAttribute("reply-message")
		assert.Len(t, msgs, 3)

		// Remove all Reply-Message attributes
		removed := pkt.RemoveAttributeByName("reply-message")
		assert.Equal(t, 3, removed)

		// Verify they were removed
		msgs = pkt.GetAttribute("reply-message")
		assert.Len(t, msgs, 0)

		// Verify other attributes still exist
		timeout := pkt.GetAttribute("session-timeout")
		assert.Len(t, timeout, 1)
	})

	t.Run("remove vendor attribute", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 2, dict)

		// Add multiple ERX-Service-Activate attributes
		require.NoError(t, pkt.AddAttributeByName("erx-service-activate:1", "Service 1"))
		require.NoError(t, pkt.AddAttributeByName("erx-service-activate:1", "Service 2"))
		require.NoError(t, pkt.AddAttributeByName("erx-primary-dns", "8.8.8.8"))

		// Verify they were added
		services := pkt.GetAttribute("erx-service-activate")
		assert.Len(t, services, 2)

		// Remove all ERX-Service-Activate attributes
		removed := pkt.RemoveAttributeByName("erx-service-activate")
		assert.Equal(t, 2, removed)

		// Verify they were removed
		services = pkt.GetAttribute("erx-service-activate")
		assert.Len(t, services, 0)

		// Verify other vendor attributes still exist
		dns := pkt.GetAttribute("erx-primary-dns")
		assert.Len(t, dns, 1)
	})

	t.Run("remove non-existent attribute", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 3, dict)

		pkt.AddAttributeByName("reply-message", "Test")

		// Try to remove attribute that doesn't exist
		removed := pkt.RemoveAttributeByName("session-timeout")
		assert.Equal(t, 0, removed)

		// Verify existing attributes weren't affected
		msgs := pkt.GetAttribute("reply-message")
		assert.Len(t, msgs, 1)
	})

	t.Run("remove with no dictionary", func(t *testing.T) {
		pkt := NewPacket(CodeAccessAccept, 4)

		// Try to remove without dictionary
		removed := pkt.RemoveAttributeByName("reply-message")
		assert.Equal(t, 0, removed)
	})
}

func TestGetAttributeStringWithMultiline(t *testing.T) {
	t.Run("multiline vendor attribute automatic join", func(t *testing.T) {
		dict := NewDictionary()

		// Add Juniper vendor with multiline attribute
		juniperVendor := &VendorDefinition{
			ID:   2636,
			Name: "juniper",
			Attributes: []*AttributeDefinition{
				{
					ID:        1,
					Name:      "juniper-user-permissions",
					DataType:  DataTypeString,
					Multiline: true,
				},
			},
		}
		require.NoError(t, dict.AddVendor(juniperVendor))

		// Create packet with multiline VSA
		pkt := NewPacket(CodeAccessAccept, 1)
		pkt.Dict = dict

		// Simulate split multiline attribute
		permissions := []string{
			"access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret<contd>",
			" secret-control security security-control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation<contd>",
			" idp-profiler-operation pgcp-session-mirroring pgcp-session-mirroring-control unified-edge unified-edge-control",
		}

		// Add each part as separate VSA
		for _, perm := range permissions {
			va := NewVendorAttribute(2636, 1, []byte(perm))
			attr := va.ToVSA()
			pkt.AddAttribute(attr)
		}

		// Use GetAttributeString which should automatically join
		result := pkt.GetAttributeString("juniper-user-permissions")

		expected := JoinMultilineAttribute(permissions)
		assert.Equal(t, expected, result)
		assert.NotContains(t, result, "<contd>")
	})

	t.Run("non-multiline attribute returns first value", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

		pkt := NewPacket(CodeAccessAccept, 1)
		pkt.Dict = dict

		// Add multiple Reply-Message attributes (not marked as multiline)
		pkt.AddAttribute(NewAttribute(18, []byte("First message")))
		pkt.AddAttribute(NewAttribute(18, []byte("Second message")))

		result := pkt.GetAttributeString("reply-message")
		assert.Equal(t, "First message", result)
	})

	t.Run("single value multiline attribute", func(t *testing.T) {
		dict := NewDictionary()

		vendor := &VendorDefinition{
			ID:   2636,
			Name: "juniper",
			Attributes: []*AttributeDefinition{
				{
					ID:        1,
					Name:      "juniper-user-permissions",
					DataType:  DataTypeString,
					Multiline: true,
				},
			},
		}
		require.NoError(t, dict.AddVendor(vendor))

		pkt := NewPacket(CodeAccessAccept, 1)
		pkt.Dict = dict

		// Single value that fits in one attribute
		singleValue := "access admin shell"
		va := NewVendorAttribute(2636, 1, []byte(singleValue))
		attr := va.ToVSA()
		pkt.AddAttribute(attr)

		result := pkt.GetAttributeString("juniper-user-permissions")
		assert.Equal(t, singleValue, result)
	})

	t.Run("attribute not found returns empty string", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddStandardAttributes(StandardRFCAttributes))

		pkt := NewPacket(CodeAccessAccept, 1)
		pkt.Dict = dict

		result := pkt.GetAttributeString("non-existent-attribute")
		assert.Equal(t, "", result)
	})
}

func TestMessageAuthenticator(t *testing.T) {
	secret := []byte("testing123")

	t.Run("calculate and verify for Access-Request", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		// Set a request authenticator
		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))
		pkt.SetAuthenticator(reqAuth)

		// Add Message-Authenticator
		pkt.AddMessageAuthenticator(secret, reqAuth)

		// Verify it
		assert.True(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("calculate and verify for Access-Accept", func(t *testing.T) {
		// Request authenticator from the original request
		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))

		pkt := NewPacket(CodeAccessAccept, 1)
		pkt.AddAttribute(NewAttribute(18, []byte("Hello, World!"))) // Reply-Message

		// Add Message-Authenticator
		pkt.AddMessageAuthenticator(secret, reqAuth)

		// Verify it
		assert.True(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("verify fails with wrong secret", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))
		pkt.SetAuthenticator(reqAuth)

		// Add Message-Authenticator with correct secret
		pkt.AddMessageAuthenticator(secret, reqAuth)

		// Try to verify with wrong secret
		wrongSecret := []byte("wrongsecret")
		assert.False(t, pkt.VerifyMessageAuthenticator(wrongSecret, reqAuth))
	})

	t.Run("verify fails with tampered packet", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))
		pkt.SetAuthenticator(reqAuth)

		// Add Message-Authenticator
		pkt.AddMessageAuthenticator(secret, reqAuth)

		// Tamper with an attribute
		pkt.AddAttribute(NewAttribute(6, []byte("1"))) // Service-Type

		// Verification should fail
		assert.False(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("verify fails with no Message-Authenticator", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))

		// No Message-Authenticator added
		assert.False(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("verify fails with invalid length", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		// Add Message-Authenticator with wrong length
		pkt.AddAttribute(NewAttribute(80, []byte("short")))

		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))

		assert.False(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("calculate with multiple attributes", func(t *testing.T) {
		pkt := NewPacket(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 0, 2, 1})) // NAS-IP-Address
		pkt.AddAttribute(NewAttribute(5, []byte{0, 0, 0, 1}))   // NAS-Port

		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))
		pkt.SetAuthenticator(reqAuth)

		// Add Message-Authenticator
		pkt.AddMessageAuthenticator(secret, reqAuth)

		// Verify it
		assert.True(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})
}

func BenchmarkPacketCreation(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = NewPacket(CodeAccessRequest, 1)
		}
	})
}

func BenchmarkPacketWithAttributes(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pkt := NewPacket(CodeAccessRequest, 1)
			pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
			pkt.AddAttribute(NewAttribute(2, []byte("password123")))
			pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))
		}
	})
}

func BenchmarkPacketWithDictionary(b *testing.B) {
	dict, _ := NewDefault()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
			_ = pkt.AddAttributeByName("user-name", "testuser")
			_ = pkt.AddAttributeByName("nas-ip-address", "192.168.1.1")
		}
	})
}

func BenchmarkAuthenticatorCalculation(b *testing.B) {
	pkt := NewPacket(CodeAccessRequest, 1)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
	secret := []byte("testing123")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = pkt.CalculateRequestAuthenticator(secret)
		}
	})
}

func BenchmarkMessageAuthenticator(b *testing.B) {
	secret := []byte("testing123")
	var reqAuth [16]byte

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pkt := NewPacket(CodeAccessRequest, 1)
			pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
			pkt.AddMessageAuthenticator(secret, reqAuth)
		}
	})
}

func BenchmarkGetAttribute(b *testing.B) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
	})

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = pkt.GetAttribute("user-name")
		}
	})
}

func BenchmarkVendorAttribute(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pkt := NewPacket(CodeAccessRequest, 1)
			va := NewVendorAttribute(4874, 13, []byte("8.8.8.8"))
			pkt.AddVendorAttribute(va)
		}
	})
}

func BenchmarkCompleteAccessRequest(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var i byte
		for pb.Next() {
			pkt := NewPacketWithDictionary(CodeAccessRequest, i, dict)
			_ = pkt.AddAttributeByName("user-name", "testuser")
			_ = pkt.AddAttributeByName("nas-ip-address", "192.168.1.1")
			_ = pkt.AddAttributeByName("nas-port", uint32(1234))

			reqAuth := pkt.CalculateRequestAuthenticator(secret)
			pkt.SetAuthenticator(reqAuth)

			pkt.AddMessageAuthenticator(secret, reqAuth)

			data, _ := pkt.Encode()

			decoded, _ := Decode(data)

			_ = decoded.VerifyMessageAuthenticator(secret, reqAuth)

			i++
		}
	})
}

func BenchmarkCompleteAccessResponse(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")
	var reqAuth [16]byte
	copy(reqAuth[:], []byte("1234567890123456"))

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var i byte
		for pb.Next() {
			pkt := NewPacketWithDictionary(CodeAccessAccept, i, dict)
			_ = pkt.AddAttributeByName("session-timeout", uint32(3600))
			_ = pkt.AddAttributeByName("framed-ip-address", "10.0.0.1")

			respAuth := pkt.CalculateResponseAuthenticator(secret, reqAuth)
			pkt.SetAuthenticator(respAuth)

			pkt.AddMessageAuthenticator(secret, reqAuth)

			_, _ = pkt.Encode()

			i++
		}
	})
}

func BenchmarkE2EAuthenticationFlow(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reqPkt := NewPacketWithDictionary(CodeAccessRequest, byte(i), dict)
		_ = reqPkt.AddAttributeByName("user-name", "testuser")
		_ = reqPkt.AddAttributeByName("nas-ip-address", "192.168.1.1")
		_ = reqPkt.AddAttributeByName("nas-port", uint32(1234))

		reqAuth := reqPkt.CalculateRequestAuthenticator(secret)
		reqPkt.SetAuthenticator(reqAuth)

		reqPkt.AddMessageAuthenticator(secret, reqAuth)

		reqData, _ := reqPkt.Encode()

		serverReqPkt, _ := Decode(reqData)

		if !serverReqPkt.VerifyMessageAuthenticator(secret, reqAuth) {
			b.Fatal("Message-Authenticator verification failed")
		}

		respPkt := NewPacketWithDictionary(CodeAccessAccept, byte(i), dict)
		_ = respPkt.AddAttributeByName("session-timeout", uint32(3600))
		_ = respPkt.AddAttributeByName("framed-ip-address", "10.0.0.1")

		respAuth := respPkt.CalculateResponseAuthenticator(secret, reqAuth)
		respPkt.SetAuthenticator(respAuth)

		respPkt.AddMessageAuthenticator(secret, reqAuth)

		respData, _ := respPkt.Encode()

		clientRespPkt, _ := Decode(respData)

		if !clientRespPkt.VerifyMessageAuthenticator(secret, reqAuth) {
			b.Fatal("Response Message-Authenticator verification failed")
		}
	}
}

func BenchmarkE2EAuthenticationFlowParallel(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		var i byte
		for pb.Next() {
			reqPkt := NewPacketWithDictionary(CodeAccessRequest, i, dict)
			_ = reqPkt.AddAttributeByName("user-name", "testuser")
			_ = reqPkt.AddAttributeByName("nas-ip-address", "192.168.1.1")
			_ = reqPkt.AddAttributeByName("nas-port", uint32(1234))

			reqAuth := reqPkt.CalculateRequestAuthenticator(secret)
			reqPkt.SetAuthenticator(reqAuth)

			reqPkt.AddMessageAuthenticator(secret, reqAuth)

			reqData, _ := reqPkt.Encode()

			serverReqPkt, _ := Decode(reqData)

			_ = serverReqPkt.VerifyMessageAuthenticator(secret, reqAuth)

			respPkt := NewPacketWithDictionary(CodeAccessAccept, i, dict)
			_ = respPkt.AddAttributeByName("session-timeout", uint32(3600))
			_ = respPkt.AddAttributeByName("framed-ip-address", "10.0.0.1")

			respAuth := respPkt.CalculateResponseAuthenticator(secret, reqAuth)
			respPkt.SetAuthenticator(respAuth)

			respPkt.AddMessageAuthenticator(secret, reqAuth)

			respData, _ := respPkt.Encode()

			clientRespPkt, _ := Decode(respData)

			_ = clientRespPkt.VerifyMessageAuthenticator(secret, reqAuth)

			i++
		}
	})
}

func BenchmarkE2EAuthenticationFlowMinimal(b *testing.B) {
	dict, _ := NewDefault()
	secret := []byte("testing123")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		reqPkt := NewPacketWithDictionary(CodeAccessRequest, byte(i), dict)
		_ = reqPkt.AddAttributeByName("user-name", "testuser")
		_ = reqPkt.AddAttributeByName("nas-ip-address", "192.168.1.1")

		reqAuth := reqPkt.CalculateRequestAuthenticator(secret)
		reqPkt.SetAuthenticator(reqAuth)

		reqData, _ := reqPkt.Encode()

		_, _ = Decode(reqData)

		respPkt := NewPacketWithDictionary(CodeAccessAccept, byte(i), dict)
		_ = respPkt.AddAttributeByName("session-timeout", uint32(3600))

		respAuth := respPkt.CalculateResponseAuthenticator(secret, reqAuth)
		respPkt.SetAuthenticator(respAuth)

		respData, _ := respPkt.Encode()

		_, _ = Decode(respData)
	}
}

func BenchmarkVSAParsingWithCache(b *testing.B) {
	pkt := NewPacket(CodeAccessRequest, 1)

	for i := 0; i < 10; i++ {
		va := NewVendorAttribute(4874, uint32(i+1), []byte("test-value"))
		pkt.AddVendorAttribute(va)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		for j := 0; j < 5; j++ {
			pkt.GetVendorAttribute(4874, 1)
			pkt.GetVendorAttribute(4874, 5)
			pkt.GetVendorAttributes(4874, 1)
		}
	}
}

func BenchmarkListAttributes(b *testing.B) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
		{ID: 4, Name: "nas-ip-address", DataType: DataTypeIPAddr},
		{ID: 5, Name: "nas-port", DataType: DataTypeInteger},
		{ID: 27, Name: "session-timeout", DataType: DataTypeInteger},
	})
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 4, Name: "erx-primary-dns", DataType: DataTypeIPAddr},
			{ID: 138, Name: "erx-dhcp-mac-addr", DataType: DataTypeString},
		},
	})

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
	pkt.AddAttribute(NewAttribute(1, []byte("testuser2"))) // Duplicate
	pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))
	pkt.AddAttribute(NewAttribute(5, []byte{0, 0, 0, 1}))
	pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{8, 8, 8, 8}))
	pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("aa:bb:cc:dd:ee:ff")))

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = pkt.ListAttributes()
	}
}

func BenchmarkJoinMultilineAttribute(b *testing.B) {
	values := []string{
		"access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret<contd>",
		" secret-control security security-control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation<contd>",
		" idp-profiler-operation pgcp-session-mirroring pgcp-session-mirroring-control unified-edge unified-edge-control",
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = JoinMultilineAttribute(values)
	}
}

func BenchmarkSplitMultilineAttribute(b *testing.B) {
	longValue := "access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-control shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session-mirroring-control unified-edge unified-edge-control"

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_ = SplitMultilineAttribute(longValue, 247)
	}
}

func BenchmarkRemoveAttributeByName(b *testing.B) {
	dict, _ := NewDefault()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		pkt.AddAttributeByName("reply-message", "Message 1")
		pkt.AddAttributeByName("reply-message", "Message 2")
		pkt.AddAttributeByName("reply-message", "Message 3")
		pkt.AddAttributeByName("session-timeout", 3600)

		pkt.RemoveAttributeByName("reply-message")
	}
}

func BenchmarkRemoveVendorAttributeByName(b *testing.B) {
	dict, _ := NewDefault()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		pkt.AddAttributeByName("erx-service-activate:1", "Service 1")
		pkt.AddAttributeByName("erx-service-activate:1", "Service 2")
		pkt.AddAttributeByName("erx-service-activate:1", "Service 3")
		pkt.AddAttributeByName("erx-primary-dns", "8.8.8.8")

		pkt.RemoveAttributeByName("erx-service-activate")
	}
}

func BenchmarkTaggedAttributeCreation(b *testing.B) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 64, Name: "tunnel-type", DataType: DataTypeInteger, HasTag: true},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		pkt.AddAttributeByName("tunnel-type:1", uint32(3))
	}
}

func BenchmarkTaggedVendorAttributeCreation(b *testing.B) {
	dict := NewDictionary()
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "erx-service-activate", DataType: DataTypeString, HasTag: true},
		},
	})

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		pkt.AddAttributeByName("erx-service-activate:1", "test-service")
	}
}

func TestVSACacheIsBounded(t *testing.T) {
	// TDD: VSA cache should not grow unbounded
	// This test verifies that the vsaCache doesn't grow beyond a reasonable size
	pkt := NewPacket(CodeAccessRequest, 1)

	// Add many VSA attributes with different indices
	for i := 0; i < 100; i++ {
		va := NewVendorAttribute(4874, uint32(i%256), []byte("test-value"))
		pkt.AddVendorAttribute(va)
	}

	// Access all VSAs to populate cache
	for i := 0; i < len(pkt.Attributes); i++ {
		pkt.GetVendorAttribute(4874, uint32(i%256))
	}

	// The cache size should be bounded (not exceed the number of actual attributes)
	// This ensures no memory leak from unbounded cache growth
	assert.LessOrEqual(t, len(pkt.vsaCache), len(pkt.Attributes),
		"VSA cache should not exceed number of attributes")
}

func TestVSACacheInvalidatedOnRemove(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)

	// Add vendor attributes
	require.NoError(t, pkt.AddAttributeByName("erx-service-activate:1", "Service 1"))
	require.NoError(t, pkt.AddAttributeByName("erx-service-activate:1", "Service 2"))

	// Access to populate cache
	attrs := pkt.GetAttribute("erx-service-activate")
	assert.Len(t, attrs, 2)

	// Cache should exist
	assert.NotNil(t, pkt.vsaCache)

	// Remove attributes
	removed := pkt.RemoveAttributeByName("erx-service-activate")
	assert.Equal(t, 2, removed)

	// Cache should be invalidated (nil)
	assert.Nil(t, pkt.vsaCache, "VSA cache should be invalidated after removal")
}

func TestEncryptTunnelPassword(t *testing.T) {
	secret := []byte("testing123")
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	t.Run("basic encryption", func(t *testing.T) {
		password := []byte("tunnel-secret")
		result := encryptTunnelPassword(password, secret, auth)

		// Result must have salt (2 bytes) + encrypted data
		assert.GreaterOrEqual(t, len(result), 2+16)

		// Salt first byte must have high bit set (RFC 2868)
		assert.True(t, result[0]&0x80 != 0, "salt high bit must be set")

		// Encrypted portion must be padded to 16-byte boundary
		encryptedLen := len(result) - 2
		assert.Equal(t, 0, encryptedLen%16)
	})

	t.Run("empty password", func(t *testing.T) {
		result := encryptTunnelPassword([]byte{}, secret, auth)

		assert.GreaterOrEqual(t, len(result), 2+16)
		assert.True(t, result[0]&0x80 != 0)
	})

	t.Run("long password spans multiple blocks", func(t *testing.T) {
		// Password longer than 15 bytes requires multiple blocks
		password := []byte("this-is-a-very-long-tunnel-password-value")
		result := encryptTunnelPassword(password, secret, auth)

		// 1 byte length + 41 bytes password = 42, padded to 48 (3 blocks)
		assert.Equal(t, 2+48, len(result))
		assert.True(t, result[0]&0x80 != 0)
	})

	t.Run("exactly 15 bytes fits one block", func(t *testing.T) {
		password := []byte("123456789012345") // 15 bytes
		result := encryptTunnelPassword(password, secret, auth)

		// 1 byte length + 15 bytes = 16, exactly one block
		assert.Equal(t, 2+16, len(result))
	})

	t.Run("different passwords produce different output", func(t *testing.T) {
		r1 := encryptTunnelPassword([]byte("pass1"), secret, auth)
		r2 := encryptTunnelPassword([]byte("pass2"), secret, auth)

		// Salt is random, so results differ even for same password
		// But encrypted portions should definitely differ
		assert.NotEqual(t, r1, r2)
	})
}

func BenchmarkAttributeValueString(b *testing.B) {
	b.Run("string", func(b *testing.B) {
		av := AttributeValue{
			DataType: DataTypeString,
			Value:    []byte("testuser"),
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = av.String()
		}
	})

	b.Run("integer", func(b *testing.B) {
		av := AttributeValue{
			DataType: DataTypeInteger,
			Value:    EncodeInteger(3600),
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = av.String()
		}
	})

	b.Run("ipaddr", func(b *testing.B) {
		av := AttributeValue{
			DataType: DataTypeIPAddr,
			Value:    []byte{192, 168, 1, 1},
		}
		b.ResetTimer()
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			_ = av.String()
		}
	})
}

func TestRemoveStandardAttributeInvalidatesVSACache(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
	}))

	pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("user-name", "alice"))
	pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{8, 8, 8, 8}))
	pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("aa:bb")))

	// Populate the index-keyed VSA cache.
	_, ok := pkt.GetVendorAttribute(4874, 4)
	require.True(t, ok)
	_, ok = pkt.GetVendorAttribute(4874, 138)
	require.True(t, ok)

	// Removing a standard attribute shifts all following indices.
	require.Equal(t, 1, pkt.RemoveAttributeByName("user-name"))

	va, ok := pkt.GetVendorAttribute(4874, 138)
	require.True(t, ok, "stale VSA cache must not hide the shifted attribute")
	assert.Equal(t, []byte("aa:bb"), va.Value)
}

func TestTaggedAttributeZeroTagRoundTrip(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 64, Name: "tunnel-type", DataType: DataTypeInteger, HasTag: true},
	}))
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "erx-service-activate", DataType: DataTypeString, HasTag: true},
		},
	}))

	t.Run("standard untagged", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		require.NoError(t, pkt.AddAttributeByName("tunnel-type", uint32(3)))

		// RFC 2868: the tag octet is always present (0x00 means unused) and
		// tagged integers carry a three-octet value.
		require.Len(t, pkt.Attributes, 1)
		assert.Equal(t, []byte{0, 0, 0, 3}, pkt.Attributes[0].Value)

		vals := pkt.GetAttribute("tunnel-type")
		require.Len(t, vals, 1)
		assert.Equal(t, uint8(0), vals[0].Tag)
		assert.Equal(t, "3", vals[0].String())
	})

	t.Run("tagged integer exceeding three octets", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		err := pkt.AddAttributeByName("tunnel-type:1", uint32(0x01000000))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "three-octet")
	})

	t.Run("vendor untagged", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		require.NoError(t, pkt.AddAttributeByName("erx-service-activate", "svc"))

		vals := pkt.GetAttribute("erx-service-activate")
		require.Len(t, vals, 1)
		assert.Equal(t, uint8(0), vals[0].Tag)
		assert.Equal(t, "svc", vals[0].String())
	})
}

func TestAddTaggedStandardAttributeByName(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 64, Name: "tunnel-type", DataType: DataTypeInteger, HasTag: true},
	}))

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("tunnel-type:3", uint32(1)))

	// RFC 2868 Section 3.1 wire format: tag(1) + three-octet value.
	require.Len(t, pkt.Attributes, 1)
	assert.Equal(t, []byte{3, 0, 0, 1}, pkt.Attributes[0].Value)

	vals := pkt.GetAttribute("tunnel-type")
	require.Len(t, vals, 1)
	assert.Equal(t, uint8(3), vals[0].Tag)
	assert.Equal(t, "1", vals[0].String())
}

func TestTaggedStringWithoutTagOctet(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 66, Name: "tunnel-client-endpoint", DataType: DataTypeString, HasTag: true},
	}))
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "erx-service-activate", DataType: DataTypeString, HasTag: true},
		},
	}))

	t.Run("standard", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		// RFC 2868 Section 3.3: a first octet greater than 0x1F is part of the
		// String field, not a tag.
		pkt.AddAttribute(NewAttribute(66, []byte("abc")))

		vals := pkt.GetAttribute("tunnel-client-endpoint")
		require.Len(t, vals, 1)
		assert.Equal(t, uint8(0), vals[0].Tag)
		assert.Equal(t, "abc", vals[0].String())
	})

	t.Run("vendor", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 1, []byte("svc")))

		vals := pkt.GetAttribute("erx-service-activate")
		require.Len(t, vals, 1)
		assert.Equal(t, uint8(0), vals[0].Tag)
		assert.Equal(t, "svc", vals[0].String())
	})
}

func TestRFC3162AttributesEndToEnd(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	require.NoError(t, pkt.AddAttributeByName("framed-ipv6-prefix", "2001:db8::/32"))
	require.NoError(t, pkt.AddAttributeByName("framed-interface-id", []byte{0, 0, 0, 0, 0, 0, 0, 1}))

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	assert.Equal(t, "2001:db8::/32", decoded.GetAttributeString("framed-ipv6-prefix"))
	assert.Equal(t, "0000:0000:0000:0001", decoded.GetAttributeString("framed-interface-id"))
}

func TestUserPasswordLengthLimit(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:         2,
			Name:       "user-password",
			DataType:   DataTypeString,
			Encryption: EncryptionUserPassword,
		},
	}))

	secret := []byte("testing123")

	t.Run("over limit rejected", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		err := pkt.AddAttributeByNameWithSecret("user-password", strings.Repeat("x", MaxUserPasswordLength+1), secret, [16]byte{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "128")
	})

	t.Run("at limit accepted", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		err := pkt.AddAttributeByNameWithSecret("user-password", strings.Repeat("x", MaxUserPasswordLength), secret, [16]byte{})
		require.NoError(t, err)
	})
}

func TestEncodeRejectsInconsistentAttributeLength(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 1)
	// 254-byte value overflows the uint8 Length field in NewAttribute.
	pkt.AddAttribute(NewAttribute(1, make([]byte, 254)))

	assert.NotPanics(t, func() {
		_, err := pkt.Encode()
		assert.Error(t, err)
	})
}

// FuzzEncryptUserPassword ensures User-Password encryption never panics and always
// produces output padded to a non-zero multiple of sixteen octets (RFC 2865 Section 5.2).
func FuzzEncryptUserPassword(f *testing.F) {
	f.Add([]byte("password"), []byte("secret"), []byte("0123456789abcdef"))
	f.Add([]byte{}, []byte{}, []byte{})
	f.Add([]byte("exactly-16-bytes"), []byte("s"), []byte("a"))

	f.Fuzz(func(t *testing.T, password, secret, auth []byte) {
		var authenticator [16]byte
		copy(authenticator[:], auth)

		encrypted := encryptUserPassword(password, secret, authenticator)
		if len(encrypted) == 0 || len(encrypted)%16 != 0 {
			t.Fatalf("encrypted length %d is not a non-zero multiple of 16", len(encrypted))
		}
		if len(encrypted) < len(password) {
			t.Fatalf("encrypted length %d shorter than password %d", len(encrypted), len(password))
		}
	})
}

// FuzzEncryptTunnelPassword ensures Tunnel-Password encryption never panics, always
// emits the two-octet salt with the high bit set, and pads to sixteen-octet blocks
// (RFC 2868 Section 3.5).
func FuzzEncryptTunnelPassword(f *testing.F) {
	f.Add([]byte("tunnel-secret"), []byte("secret"), []byte("0123456789abcdef"))
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, password, secret, auth []byte) {
		var authenticator [16]byte
		copy(authenticator[:], auth)

		encrypted := encryptTunnelPassword(password, secret, authenticator)
		if len(encrypted) < 2+16 || (len(encrypted)-2)%16 != 0 {
			t.Fatalf("encrypted length %d is not salt plus a multiple of 16", len(encrypted))
		}
		if encrypted[0]&0x80 == 0 {
			t.Fatal("salt high bit not set")
		}
	})
}

// TestJunosMultilineCapture verifies Multiline handling against a live capture from a
// vJunos router: Juniper-User-Permissions split across three VSA instances, the first
// two carrying 240 payload characters plus the literal "<contd>" continuation marker
// (247 octets total each) and the last carrying the remainder without a marker.
func TestJunosMultilineCapture(t *testing.T) {
	const fragment1 = "access access-control admin admin-control clear configure control edit field firewall firewall-control floppy interface interface-control maintenance network reset rollback routing routing-control secret secret-control security security-con"
	const fragment2 = "trol shell snmp snmp-control storage storage-control system system-control trace trace-control view view-configuration all-control flow-tap flow-tap-control flow-tap-operation idp-profiler-operation pgcp-session-mirroring pgcp-session-mirro"
	const fragment3 = "ring-control unified-edge unified-edge-control "
	full := fragment1 + fragment2 + fragment3

	require.Len(t, fragment1, 240)
	require.Len(t, fragment2, 240)
	require.Len(t, fragment1+ContinuationMarker, MaxVSAValueLength)

	dict := NewDictionary()
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   2636,
		Name: "juniper",
		Attributes: []*AttributeDefinition{
			{ID: 10, Name: "juniper-user-permissions", DataType: DataTypeString, Multiline: true},
		},
	}))

	t.Run("read joins captured fragments", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccountingRequest, 0x5c, dict)
		pkt.AddVendorAttribute(NewVendorAttribute(2636, 10, []byte(fragment1+ContinuationMarker)))
		pkt.AddVendorAttribute(NewVendorAttribute(2636, 10, []byte(fragment2+ContinuationMarker)))
		pkt.AddVendorAttribute(NewVendorAttribute(2636, 10, []byte(fragment3)))

		assert.Equal(t, full, pkt.GetAttributeString("juniper-user-permissions"))
	})

	t.Run("add auto-splits like the router", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccountingRequest, 0x5c, dict)
		require.NoError(t, pkt.AddAttributeByName("juniper-user-permissions", full))

		// Must produce exactly the on-wire fragmentation observed in the capture.
		require.Len(t, pkt.Attributes, 3)
		va1, _ := ParseVSA(pkt.Attributes[0])
		va2, _ := ParseVSA(pkt.Attributes[1])
		va3, _ := ParseVSA(pkt.Attributes[2])
		assert.Equal(t, []byte(fragment1+ContinuationMarker), va1.Value)
		assert.Equal(t, []byte(fragment2+ContinuationMarker), va2.Value)
		assert.Equal(t, []byte(fragment3), va3.Value)
	})

	t.Run("round trip through wire encoding", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccountingRequest, 0x5c, dict)
		require.NoError(t, pkt.AddAttributeByName("juniper-user-permissions", full))

		raw, err := pkt.Encode()
		require.NoError(t, err)
		decoded, err := Decode(raw)
		require.NoError(t, err)
		decoded.Dict = dict

		assert.Equal(t, full, decoded.GetAttributeString("juniper-user-permissions"))
	})

	t.Run("short multiline value stays a single instance", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccountingRequest, 1, dict)
		require.NoError(t, pkt.AddAttributeByName("juniper-user-permissions", "all"))
		require.Len(t, pkt.Attributes, 1)
		assert.Equal(t, "all", pkt.GetAttributeString("juniper-user-permissions"))
	})
}

// TestRFC2865ExampleVectors verifies the crypto and codec against the published
// example packets of RFC 2865 Section 7 (shared secret "xyzzy5461").
func TestRFC2865ExampleVectors(t *testing.T) {
	secret := []byte("xyzzy5461")

	t.Run("7.1 user nemo with User-Password", func(t *testing.T) {
		raw := mustHex(t, "01000038 0f403f94 73978057 bd83d5cb 98f4227a 01066e65 6d6f0212 0dbe708d 93d413ce 3196e43f 782a0aee 0406c0a8 01100506 00000003")

		pkt, err := Decode(raw)
		require.NoError(t, err)
		assert.Equal(t, CodeAccessRequest, pkt.Code)
		assert.Equal(t, uint8(0), pkt.Identifier)
		require.Len(t, pkt.Attributes, 4)

		// User-Password encryption known-answer per the RFC example
		expected := mustHex(t, "0dbe708d 93d413ce 3196e43f 782a0aee")
		got := encryptUserPassword([]byte("arctangent"), secret, pkt.Authenticator)
		assert.Equal(t, expected, got)
		assert.Equal(t, expected, pkt.Attributes[1].Value)

		// Re-encoding reproduces the published bytes
		reencoded, err := pkt.Encode()
		require.NoError(t, err)
		assert.Equal(t, raw, reencoded)

		// Access-Accept Response Authenticator known-answer
		respRaw := mustHex(t, "02000026 86fe220e 7624ba2a 1005f6bf 9b55e0b2 06060000 00010f06 00000000 0e06c0a8 0103")
		resp, err := Decode(respRaw)
		require.NoError(t, err)
		assert.Equal(t, resp.Authenticator, resp.CalculateResponseAuthenticator(secret, pkt.Authenticator))
	})

	t.Run("7.2 user flopsy with CHAP", func(t *testing.T) {
		raw := mustHex(t, "01010047 2aee86f0 8d0d5596 9ca5978e 0d3367a2 0108666c 6f707379 031316e9 7557c316 185895f2 93ff6344 07727504 06c0a801 10050600 00001406 06000000 02070600 000001")

		pkt, err := Decode(raw)
		require.NoError(t, err)
		assert.Equal(t, CodeAccessRequest, pkt.Code)
		require.Len(t, pkt.Attributes, 6)

		// CHAP-Password: 1 octet CHAP ident (22) + 16 octet response;
		// the CHAP challenge is the Request Authenticator
		chap := pkt.Attributes[1]
		assert.Equal(t, uint8(3), chap.Type)
		require.Len(t, chap.Value, 17)
		assert.Equal(t, uint8(22), chap.Value[0])

		respRaw := mustHex(t, "02010038 15efbc7d ab26cfa3 dc34d9c0 3c8601a4 06060000 00020706 00000001 0806ffff fffe0a06 00000002 0d060000 00010c06 000005dc")
		resp, err := Decode(respRaw)
		require.NoError(t, err)
		assert.Equal(t, resp.Authenticator, resp.CalculateResponseAuthenticator(secret, pkt.Authenticator))
	})

	t.Run("7.3 user mopsy User-Password challenge", func(t *testing.T) {
		raw := mustHex(t, "01020039 f3a47a1f 6a6d7671 0b947ab9 3041a039 01076d6f 70737902 12336575 73778289 b570885e 15084825 c50406c0 a8011005 06000000 07")

		pkt, err := Decode(raw)
		require.NoError(t, err)

		expected := mustHex(t, "33657573 778289b5 70885e15 084825c5")
		got := encryptUserPassword([]byte("challenge"), secret, pkt.Authenticator)
		assert.Equal(t, expected, got)
		assert.Equal(t, expected, pkt.Attributes[1].Value)
	})
}

// decryptTunnelPasswordForTest is the RFC 2868 Section 3.5 inverse cipher, used to
// verify our encryption against FreeRADIUS-produced ciphertexts.
func decryptTunnelPasswordForTest(t *testing.T, data, secret []byte, auth [16]byte) []byte {
	t.Helper()
	require.GreaterOrEqual(t, len(data), 2+16)
	salt := data[:2]
	enc := data[2:]
	require.Zero(t, len(enc)%16)

	hashInput := make([]byte, 0, len(secret)+18)
	hashInput = append(hashInput, secret...)
	hashInput = append(hashInput, auth[:]...)
	hashInput = append(hashInput, salt...)
	block := md5.Sum(hashInput)

	plain := make([]byte, len(enc))
	for i := 0; i < len(enc); i += 16 {
		if i > 0 {
			prev := make([]byte, 0, len(secret)+16)
			prev = append(prev, secret...)
			prev = append(prev, enc[i-16:i]...)
			block = md5.Sum(prev)
		}
		for j := range 16 {
			plain[i+j] = enc[i+j] ^ block[j]
		}
	}

	n := int(plain[0])
	require.LessOrEqual(t, n, len(plain)-1)
	return plain[1 : 1+n]
}

// TestFreeRADIUSEncryptVectors ports known-answer vectors from the FreeRADIUS unit
// tests (src/tests/unit/protocols/radius: rfc2868.txt, ascend.txt), which use the
// shared secret "testing123" and authenticator 0x000102...0f.
func TestFreeRADIUSEncryptVectors(t *testing.T) {
	secret := []byte("testing123")
	auth := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	t.Run("user-password bob", func(t *testing.T) {
		expected := mustHex(t, "f4816bca 74fd7a1a 10460724 0014828b")
		assert.Equal(t, expected, encryptUserPassword([]byte("bob"), secret, auth))
	})

	t.Run("ascend-send-secret foo", func(t *testing.T) {
		expected := mustHex(t, "ce8dbb09 a0cdc29c caf1bdcb 2541f770")
		assert.Equal(t, expected, encryptAscendSecret([]byte("foo"), secret, auth))
	})

	t.Run("ascend-send-secret truncated to sixteen", func(t *testing.T) {
		expected := mustHex(t, "ce8dbb29 95fbf5a4 f390dfa8 41249140")
		assert.Equal(t, expected, encryptAscendSecret([]byte("foo 56789abcdef012"), secret, auth))
	})

	t.Run("tunnel-password decode vectors", func(t *testing.T) {
		// Attribute values with the leading zero tag octet stripped.
		vectors := []struct {
			cipher string
			plain  string
		}{
			{"9973051d e6c55730 7dacd5da a599f4e2 6e7e", "foo"},
			{"9dc5c469 233a1657 b35c9782 3c97ec6b 7ef1", "bar"},
			{"c06f255f 09b7dc0e 4a1a4656 05f48f7c 0ba4", "barbar"},
		}

		for _, v := range vectors {
			got := decryptTunnelPasswordForTest(t, mustHex(t, v.cipher), secret, auth)
			assert.Equal(t, v.plain, string(got))
		}
	})

	t.Run("tunnel-password round trip through reference decrypt", func(t *testing.T) {
		for _, password := range []string{"", "foo", "exactly-15-char", "a-password-longer-than-one-block"} {
			encrypted := encryptTunnelPassword([]byte(password), secret, auth)
			got := decryptTunnelPasswordForTest(t, encrypted, secret, auth)
			assert.Equal(t, password, string(got))
		}
	})
}

func TestEncryptAscendSecret(t *testing.T) {
	secret := []byte("testing123")
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	// FreeRADIUS make_secret reference: digest = MD5(authenticator + secret),
	// first min(len(value),16) octets XORed with the value, output is 16 octets.
	expected := func(value []byte) []byte {
		digest := md5.Sum(append(append([]byte{}, auth[:]...), secret...))
		for i := 0; i < len(value) && i < 16; i++ {
			digest[i] ^= value[i]
		}
		return digest[:]
	}

	t.Run("short value", func(t *testing.T) {
		value := []byte("secretval")
		got := encryptAscendSecret(value, secret, auth)
		require.Len(t, got, 16)
		assert.Equal(t, expected(value), got)
	})

	t.Run("empty value", func(t *testing.T) {
		got := encryptAscendSecret(nil, secret, auth)
		require.Len(t, got, 16)
		assert.Equal(t, expected(nil), got)
	})

	t.Run("value truncated to sixteen octets", func(t *testing.T) {
		value := []byte("exactly-16-bytes-plus-overflow")
		got := encryptAscendSecret(value, secret, auth)
		require.Len(t, got, 16)
		assert.Equal(t, expected(value), got)
	})
}

// FuzzEncryptAscendSecret ensures the Ascend-Secret cipher never panics and always
// produces exactly sixteen octets.
func FuzzEncryptAscendSecret(f *testing.F) {
	f.Add([]byte("value"), []byte("secret"), []byte("0123456789abcdef"))
	f.Add([]byte{}, []byte{}, []byte{})

	f.Fuzz(func(t *testing.T, value, secret, auth []byte) {
		var authenticator [16]byte
		copy(authenticator[:], auth)

		got := encryptAscendSecret(value, secret, authenticator)
		if len(got) != 16 {
			t.Fatalf("output length %d, want 16", len(got))
		}
	})
}

func BenchmarkEncryptAscendSecret(b *testing.B) {
	value := []byte("ascend-secret-value")
	secret := []byte("testing123")
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b.ReportAllocs()
	for b.Loop() {
		_ = encryptAscendSecret(value, secret, auth)
	}
}

func BenchmarkEncryptUserPassword(b *testing.B) {
	password := []byte("user-password-value")
	secret := []byte("testing123")
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b.ReportAllocs()
	for b.Loop() {
		_ = encryptUserPassword(password, secret, auth)
	}
}

func BenchmarkEncryptTunnelPassword(b *testing.B) {
	password := []byte("tunnel-password-value")
	secret := []byte("testing123")
	auth := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	b.ReportAllocs()
	for b.Loop() {
		_ = encryptTunnelPassword(password, secret, auth)
	}
}

func BenchmarkAddAttributeByName(b *testing.B) {
	dict, err := NewDefault()
	require.NoError(b, err)

	b.Run("standard", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
			_ = pkt.AddAttributeByName("user-name", "benchuser")
		}
	})

	b.Run("vendor", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
			_ = pkt.AddAttributeByName("cisco-avpair", "shell:priv-lvl=15")
		}
	})

	b.Run("tagged standard", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			pkt := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
			_ = pkt.AddAttributeByName("tunnel-type:1", uint32(13))
		}
	})
}

func TestMessageAuthenticatorRFC5176Ordering(t *testing.T) {
	secret := []byte("testing123")

	for _, code := range []Code{CodeCoARequest, CodeDisconnectRequest, CodeAccountingRequest} {
		t.Run(code.String(), func(t *testing.T) {
			pkt := NewPacket(code, 7)
			pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
			// Nonzero authenticator field and nonzero parameter prove the
			// implementation uses sixteen zero octets regardless of either.
			pkt.SetAuthenticator([16]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9})
			pkt.AddMessageAuthenticator(secret, [16]byte{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8})

			// RFC 5176 Section 3.4: the Message-Authenticator is computed with the
			// Request Authenticator field and the attribute itself both zeroed.
			mac := hmac.New(md5.New, secret)
			mac.Write(pkt.buildPacketBytes([16]byte{}, true))
			expectedMA := mac.Sum(nil)

			attrs := pkt.GetAttributes(AttributeTypeMessageAuthenticator)
			require.Len(t, attrs, 1)
			assert.Equal(t, expectedMA, attrs[0].Value)
			assert.True(t, pkt.VerifyMessageAuthenticator(secret, [16]byte{1, 2, 3}))

			// RFC 5176 Section 3.4: the Request Authenticator is then computed
			// over the packet carrying the real Message-Authenticator value.
			sum := md5.Sum(append(pkt.buildPacketBytes([16]byte{}, false), secret...))
			assert.Equal(t, sum, pkt.CalculateRequestAuthenticator(secret))
		})
	}
}
