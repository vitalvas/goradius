package packet

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
)

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
			pkt := New(tt.code, tt.identifier)
			assert.Equal(t, tt.code, pkt.Code)
			assert.Equal(t, tt.identifier, pkt.Identifier)
			assert.Equal(t, uint16(PacketHeaderLength), pkt.Length)
			assert.Empty(t, pkt.Attributes)
		})
	}
}

func TestPacketAddAttribute(t *testing.T) {
	pkt := New(CodeAccessRequest, 1)

	attr := NewAttribute(1, []byte("testuser"))
	pkt.AddAttribute(attr)

	assert.Len(t, pkt.Attributes, 1)
	assert.Equal(t, uint8(1), pkt.Attributes[0].Type)
	assert.Equal(t, []byte("testuser"), pkt.Attributes[0].Value)
	assert.Equal(t, PacketHeaderLength+uint16(attr.Length), pkt.Length)
}

func TestPacketGetAttribute(t *testing.T) {
	pkt := New(CodeAccessRequest, 1)

	attr := NewAttribute(1, []byte("testuser"))
	pkt.AddAttribute(attr)

	attrs := pkt.GetAttributes(1)
	assert.Len(t, attrs, 1)
	assert.Equal(t, []byte("testuser"), attrs[0].Value)

	attrs = pkt.GetAttributes(99)
	assert.Empty(t, attrs)
}

func TestPacketGetAttributes(t *testing.T) {
	pkt := New(CodeAccessRequest, 1)

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
	pkt := New(CodeAccessRequest, 1)

	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
	pkt.AddAttribute(NewAttribute(2, []byte("testpass")))

	removed := pkt.RemoveAttribute(1)
	assert.True(t, removed)
	assert.Len(t, pkt.Attributes, 1)

	removed = pkt.RemoveAttribute(99)
	assert.False(t, removed)
}

func TestPacketRemoveAttributes(t *testing.T) {
	pkt := New(CodeAccessRequest, 1)

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
				return New(CodeAccessRequest, 1)
			},
			wantErr: false,
		},
		{
			name: "invalid code",
			setup: func() *Packet {
				pkt := New(CodeAccessRequest, 1)
				pkt.Code = 99
				return pkt
			},
			wantErr: true,
		},
		{
			name: "packet too short",
			setup: func() *Packet {
				pkt := New(CodeAccessRequest, 1)
				pkt.Length = 10
				return pkt
			},
			wantErr: true,
		},
		{
			name: "packet too long",
			setup: func() *Packet {
				pkt := New(CodeAccessRequest, 1)
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
	pkt := New(CodeAccessRequest, 1)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

	secret := []byte("testing123")

	// Calculate request authenticator
	reqAuth := pkt.CalculateRequestAuthenticator(secret)
	assert.Len(t, reqAuth, AuthenticatorLength)

	// Create response
	resp := New(CodeAccessAccept, 1)
	resp.AddAttribute(NewAttribute(18, []byte("Welcome")))

	// Calculate response authenticator
	respAuth := resp.CalculateResponseAuthenticator(secret, reqAuth)
	assert.Len(t, respAuth, AuthenticatorLength)

	// Response auth should be different from request auth
	assert.NotEqual(t, reqAuth, respAuth)
}

func TestPacketWithDictionary(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{
			ID:       1,
			Name:     "User-Name",
			DataType: dictionary.DataTypeString,
		},
		{
			ID:       8,
			Name:     "Framed-IP-Address",
			DataType: dictionary.DataTypeIPAddr,
		},
	})

	pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
	assert.NotNil(t, pkt.Dict)

	pkt.AddAttributeByName("User-Name", "testuser")
	pkt.AddAttributeByName("Framed-IP-Address", "192.0.2.10")

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
	pkt := New(CodeAccessRequest, 1)

	va := NewVendorAttribute(4874, 13, []byte("8.8.8.8"))
	pkt.AddVendorAttribute(va)

	assert.Len(t, pkt.Attributes, 1)
	assert.Equal(t, uint8(26), pkt.Attributes[0].Type) // VSA type

	foundVA, ok := pkt.GetVendorAttribute(4874, 13)
	assert.True(t, ok)
	assert.Equal(t, uint32(4874), foundVA.VendorID)
	assert.Equal(t, uint8(13), foundVA.VendorType)
	assert.Equal(t, []byte("8.8.8.8"), foundVA.Value)
}

func TestPacketTaggedVendorAttributes(t *testing.T) {
	pkt := New(CodeAccessRequest, 1)

	va := NewTaggedVendorAttribute(4874, 1, 3, []byte("test-service"))
	pkt.AddVendorAttribute(va)

	foundVA, ok := pkt.GetVendorAttribute(4874, 1)
	assert.True(t, ok)
	assert.Equal(t, uint8(3), foundVA.Tag)
	assert.Equal(t, []byte("test-service"), foundVA.GetValue())
}

func TestPacketString(t *testing.T) {
	pkt := New(CodeAccessRequest, 42)
	pkt.AddAttribute(NewAttribute(1, []byte("test")))

	str := pkt.String()
	assert.Contains(t, str, "Access-Request")
	assert.Contains(t, str, "ID=42")
	assert.Contains(t, str, "Attributes=1")
}

func TestPacketListAttributes(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{ID: 1, Name: "User-Name", DataType: dictionary.DataTypeString},
		{ID: 4, Name: "NAS-IP-Address", DataType: dictionary.DataTypeIPAddr},
		{ID: 8, Name: "Framed-IP-Address", DataType: dictionary.DataTypeIPAddr},
	})
	dict.AddVendor(&dictionary.VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*dictionary.AttributeDefinition{
			{ID: 4, Name: "ERX-Primary-Dns", DataType: dictionary.DataTypeIPAddr},
			{ID: 138, Name: "ERX-Dhcp-Mac-Addr", DataType: dictionary.DataTypeString},
		},
	})

	t.Run("no dictionary", func(t *testing.T) {
		pkt := New(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		result := pkt.ListAttributes()
		assert.Empty(t, result)
	})

	t.Run("with dictionary - standard attributes", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "User-Name")
		assert.Contains(t, result, "NAS-IP-Address")
	})

	t.Run("with dictionary - duplicate attributes", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser1")))
		pkt.AddAttribute(NewAttribute(1, []byte("testuser2")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "User-Name")
		assert.Contains(t, result, "NAS-IP-Address")
	})

	t.Run("with dictionary - vendor attributes", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("aa:bb:cc:dd:ee:ff")))

		result := pkt.ListAttributes()
		assert.Len(t, result, 3)
		assert.Contains(t, result, "User-Name")
		assert.Contains(t, result, "ERX-Primary-Dns")
		assert.Contains(t, result, "ERX-Dhcp-Mac-Addr")
	})

	t.Run("with dictionary - unknown attributes skipped", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddAttribute(NewAttribute(99, []byte("unknown")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "User-Name")
		assert.Contains(t, result, "NAS-IP-Address")
		assert.NotContains(t, result, "unknown")
	})

	t.Run("with dictionary - unknown vendor attributes skipped", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))
		pkt.AddVendorAttribute(NewVendorAttribute(9999, 1, []byte("unknown vendor")))

		result := pkt.ListAttributes()
		assert.Len(t, result, 2)
		assert.Contains(t, result, "User-Name")
		assert.Contains(t, result, "ERX-Primary-Dns")
	})

	t.Run("empty packet", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)

		result := pkt.ListAttributes()
		assert.Empty(t, result)
	})
}

func TestPacketGetAttributeByName(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{ID: 1, Name: "User-Name", DataType: dictionary.DataTypeString},
		{ID: 4, Name: "NAS-IP-Address", DataType: dictionary.DataTypeIPAddr},
		{ID: 27, Name: "Session-Timeout", DataType: dictionary.DataTypeInteger},
	})
	dict.AddVendor(&dictionary.VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*dictionary.AttributeDefinition{
			{ID: 4, Name: "ERX-Primary-Dns", DataType: dictionary.DataTypeIPAddr},
			{ID: 138, Name: "ERX-Dhcp-Mac-Addr", DataType: dictionary.DataTypeString},
		},
	})

	t.Run("no dictionary", func(t *testing.T) {
		pkt := New(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		result := pkt.GetAttribute("User-Name")
		assert.Empty(t, result)
	})

	t.Run("standard attribute - single value", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		values := pkt.GetAttribute("User-Name")
		assert.Len(t, values, 1)
		assert.Equal(t, "User-Name", values[0].Name)
		assert.Equal(t, uint8(1), values[0].Type)
		assert.Equal(t, dictionary.DataTypeString, values[0].DataType)
		assert.Equal(t, []byte("testuser"), values[0].Value)
		assert.False(t, values[0].IsVSA)
	})

	t.Run("standard attribute - multiple values", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("user1")))
		pkt.AddAttribute(NewAttribute(1, []byte("user2")))
		pkt.AddAttribute(NewAttribute(1, []byte("user3")))

		values := pkt.GetAttribute("User-Name")
		assert.Len(t, values, 3)
		assert.Equal(t, []byte("user1"), values[0].Value)
		assert.Equal(t, []byte("user2"), values[1].Value)
		assert.Equal(t, []byte("user3"), values[2].Value)
	})

	t.Run("VSA attribute - single value", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))

		values := pkt.GetAttribute("ERX-Primary-Dns")
		assert.Len(t, values, 1)
		assert.Equal(t, "ERX-Primary-Dns", values[0].Name)
		assert.Equal(t, uint8(26), values[0].Type)
		assert.Equal(t, dictionary.DataTypeIPAddr, values[0].DataType)
		assert.Equal(t, []byte{192, 0, 2, 1}, values[0].Value)
		assert.True(t, values[0].IsVSA)
		assert.Equal(t, uint32(4874), values[0].VendorID)
		assert.Equal(t, uint8(4), values[0].VendorType)
	})

	t.Run("VSA attribute - multiple values", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("aa:bb:cc:dd:ee:ff")))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 138, []byte("11:22:33:44:55:66")))

		values := pkt.GetAttribute("ERX-Dhcp-Mac-Addr")
		assert.Len(t, values, 2)
		assert.Equal(t, []byte("aa:bb:cc:dd:ee:ff"), values[0].Value)
		assert.Equal(t, []byte("11:22:33:44:55:66"), values[1].Value)
		assert.True(t, values[0].IsVSA)
		assert.True(t, values[1].IsVSA)
	})

	t.Run("attribute not found", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		values := pkt.GetAttribute("NonExistent")
		assert.Empty(t, values)
	})

	t.Run("attribute not in dictionary", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(99, []byte("unknown")))

		values := pkt.GetAttribute("Unknown-Attribute")
		assert.Empty(t, values)
	})

	t.Run("mixed attributes", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessRequest, 1, dict)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
		pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))
		pkt.AddVendorAttribute(NewVendorAttribute(4874, 4, []byte{192, 0, 2, 1}))

		userValues := pkt.GetAttribute("User-Name")
		assert.Len(t, userValues, 1)
		assert.Equal(t, "User-Name", userValues[0].Name)

		nasValues := pkt.GetAttribute("NAS-IP-Address")
		assert.Len(t, nasValues, 1)
		assert.Equal(t, "NAS-IP-Address", nasValues[0].Name)

		dnsValues := pkt.GetAttribute("ERX-Primary-Dns")
		assert.Len(t, dnsValues, 1)
		assert.Equal(t, "ERX-Primary-Dns", dnsValues[0].Name)
		assert.True(t, dnsValues[0].IsVSA)
	})
}

func TestAttributeValueString(t *testing.T) {
	t.Run("string type", func(t *testing.T) {
		av := AttributeValue{
			DataType: dictionary.DataTypeString,
			Value:    []byte("testuser"),
		}
		assert.Equal(t, "testuser", av.String())
	})

	t.Run("integer type", func(t *testing.T) {
		av := AttributeValue{
			DataType: dictionary.DataTypeInteger,
			Value:    EncodeInteger(3600),
		}
		assert.Equal(t, "3600", av.String())
	})

	t.Run("ipaddr type", func(t *testing.T) {
		av := AttributeValue{
			DataType: dictionary.DataTypeIPAddr,
			Value:    []byte{192, 168, 1, 1},
		}
		assert.Equal(t, "192.168.1.1", av.String())
	})

	t.Run("ipv6addr type", func(t *testing.T) {
		ip := net.ParseIP("2001:db8::1")
		encoded, _ := EncodeIPv6Addr(ip)
		av := AttributeValue{
			DataType: dictionary.DataTypeIPv6Addr,
			Value:    encoded,
		}
		assert.Equal(t, "2001:db8::1", av.String())
	})

	t.Run("date type", func(t *testing.T) {
		now := time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC)
		av := AttributeValue{
			DataType: dictionary.DataTypeDate,
			Value:    EncodeDate(now),
		}
		// DecodeDate returns local time, so convert expected time to local
		expected := time.Unix(now.Unix(), 0).Format(time.RFC3339)
		assert.Equal(t, expected, av.String())
	})

	t.Run("octets type", func(t *testing.T) {
		av := AttributeValue{
			DataType: dictionary.DataTypeOctets,
			Value:    []byte{0x1a, 0x2b, 0x3c, 0x4d},
		}
		assert.Equal(t, "0x1a2b3c4d", av.String())
	})

	t.Run("unknown type", func(t *testing.T) {
		av := AttributeValue{
			DataType: dictionary.DataType("unknown"),
			Value:    []byte{0xaa, 0xbb, 0xcc},
		}
		assert.Equal(t, "0xaabbcc", av.String())
	})

	t.Run("invalid integer", func(t *testing.T) {
		av := AttributeValue{
			DataType: dictionary.DataTypeInteger,
			Value:    []byte{0x01}, // Invalid length for integer
		}
		assert.Equal(t, "0x01", av.String())
	})

	t.Run("invalid ipaddr", func(t *testing.T) {
		av := AttributeValue{
			DataType: dictionary.DataTypeIPAddr,
			Value:    []byte{0x01, 0x02}, // Invalid length for IP
		}
		assert.Equal(t, "0x0102", av.String())
	})
}

func TestArrayAttributeHandling(t *testing.T) {
	dict := dictionary.New()
	dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{ID: 18, Name: "Reply-Message", DataType: dictionary.DataTypeString},
	})

	pkt := NewWithDictionary(CodeAccessAccept, 1, dict)

	t.Run("single value as array", func(t *testing.T) {
		// Single value should still work
		pkt.AddAttributeByName("Reply-Message", "Single message")

		attrs := pkt.GetAttribute("Reply-Message")
		assert.Len(t, attrs, 1)
		assert.Equal(t, "Single message", attrs[0].String())
	})

	t.Run("slice of strings", func(t *testing.T) {
		pkt2 := NewWithDictionary(CodeAccessAccept, 2, dict)

		// Pass a slice of strings
		messages := []string{"First message", "Second message", "Third message"}
		pkt2.AddAttributeByName("Reply-Message", messages)

		attrs := pkt2.GetAttribute("Reply-Message")
		assert.Len(t, attrs, 3)
		assert.Equal(t, "First message", attrs[0].String())
		assert.Equal(t, "Second message", attrs[1].String())
		assert.Equal(t, "Third message", attrs[2].String())
	})

	t.Run("slice of interfaces", func(t *testing.T) {
		pkt3 := NewWithDictionary(CodeAccessAccept, 3, dict)

		// Pass a slice of interface{}
		messages := []interface{}{"Message one", "Message two"}
		pkt3.AddAttributeByName("Reply-Message", messages)

		attrs := pkt3.GetAttribute("Reply-Message")
		assert.Len(t, attrs, 2)
		assert.Equal(t, "Message one", attrs[0].String())
		assert.Equal(t, "Message two", attrs[1].String())
	})
}

func TestVendorArrayAttributeHandling(t *testing.T) {
	vendor := &dictionary.VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*dictionary.AttributeDefinition{
			{ID: 1, Name: "ERX-Service-Activate", DataType: dictionary.DataTypeString, HasTag: true},
			{ID: 4, Name: "ERX-Primary-Dns", DataType: dictionary.DataTypeIPAddr, HasTag: false},
		},
	}

	dict := dictionary.New()
	require.NoError(t, dict.AddVendor(vendor))

	pkt := NewWithDictionary(CodeAccessAccept, 1, dict)

	t.Run("single vendor value with tag", func(t *testing.T) {
		pkt.AddAttributeByName("ERX-Service-Activate:1", "service1")

		attrs := pkt.GetAttribute("ERX-Service-Activate")
		assert.Len(t, attrs, 1)
		assert.Equal(t, uint8(1), attrs[0].Tag)
		assert.Equal(t, "service1", attrs[0].String())
	})

	t.Run("multiple vendor values with tag", func(t *testing.T) {
		pkt2 := NewWithDictionary(CodeAccessAccept, 2, dict)

		services := []string{"service-a", "service-b", "service-c"}
		pkt2.AddAttributeByName("ERX-Service-Activate:1", services)

		attrs := pkt2.GetAttribute("ERX-Service-Activate")
		assert.Len(t, attrs, 3)
		assert.Equal(t, uint8(1), attrs[0].Tag)
		assert.Equal(t, "service-a", attrs[0].String())
		assert.Equal(t, uint8(1), attrs[1].Tag)
		assert.Equal(t, "service-b", attrs[1].String())
		assert.Equal(t, uint8(1), attrs[2].Tag)
		assert.Equal(t, "service-c", attrs[2].String())
	})

	t.Run("non-tagged vendor attributes with IP addresses", func(t *testing.T) {
		pkt3 := NewWithDictionary(CodeAccessAccept, 3, dict)

		dnsServers := []string{"8.8.8.8", "8.8.4.4", "1.1.1.1"}
		pkt3.AddAttributeByName("ERX-Primary-Dns", dnsServers)

		attrs := pkt3.GetAttribute("ERX-Primary-Dns")
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
	dict, err := dictionaries.NewDefault()
	require.NoError(t, err)

	t.Run("remove standard attribute", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessAccept, 1, dict)

		// Add multiple Reply-Message attributes
		pkt.AddAttributeByName("Reply-Message", "Message 1")
		pkt.AddAttributeByName("Reply-Message", "Message 2")
		pkt.AddAttributeByName("Reply-Message", "Message 3")
		pkt.AddAttributeByName("Session-Timeout", 3600)

		// Verify all were added
		msgs := pkt.GetAttribute("Reply-Message")
		assert.Len(t, msgs, 3)

		// Remove all Reply-Message attributes
		removed := pkt.RemoveAttributeByName("Reply-Message")
		assert.Equal(t, 3, removed)

		// Verify they were removed
		msgs = pkt.GetAttribute("Reply-Message")
		assert.Len(t, msgs, 0)

		// Verify other attributes still exist
		timeout := pkt.GetAttribute("Session-Timeout")
		assert.Len(t, timeout, 1)
	})

	t.Run("remove vendor attribute", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessAccept, 2, dict)

		// Add multiple ERX-Service-Activate attributes
		pkt.AddAttributeByName("ERX-Service-Activate:1", "Service 1")
		pkt.AddAttributeByName("ERX-Service-Activate:1", "Service 2")
		pkt.AddAttributeByName("ERX-Primary-Dns", "8.8.8.8")

		// Verify they were added
		services := pkt.GetAttribute("ERX-Service-Activate")
		assert.Len(t, services, 2)

		// Remove all ERX-Service-Activate attributes
		removed := pkt.RemoveAttributeByName("ERX:ERX-Service-Activate")
		assert.Equal(t, 2, removed)

		// Verify they were removed
		services = pkt.GetAttribute("ERX-Service-Activate")
		assert.Len(t, services, 0)

		// Verify other vendor attributes still exist
		dns := pkt.GetAttribute("ERX-Primary-Dns")
		assert.Len(t, dns, 1)
	})

	t.Run("remove non-existent attribute", func(t *testing.T) {
		pkt := NewWithDictionary(CodeAccessAccept, 3, dict)

		pkt.AddAttributeByName("Reply-Message", "Test")

		// Try to remove attribute that doesn't exist
		removed := pkt.RemoveAttributeByName("Session-Timeout")
		assert.Equal(t, 0, removed)

		// Verify existing attributes weren't affected
		msgs := pkt.GetAttribute("Reply-Message")
		assert.Len(t, msgs, 1)
	})

	t.Run("remove with no dictionary", func(t *testing.T) {
		pkt := New(CodeAccessAccept, 4)

		// Try to remove without dictionary
		removed := pkt.RemoveAttributeByName("Reply-Message")
		assert.Equal(t, 0, removed)
	})
}

func TestGetAttributeStringWithMultiline(t *testing.T) {
	t.Run("multiline vendor attribute automatic join", func(t *testing.T) {
		dict := dictionary.New()

		// Add Juniper vendor with multiline attribute
		juniperVendor := &dictionary.VendorDefinition{
			ID:   2636,
			Name: "Juniper",
			Attributes: []*dictionary.AttributeDefinition{
				{
					ID:        1,
					Name:      "Juniper-User-Permissions",
					DataType:  dictionary.DataTypeString,
					Multiline: true,
				},
			},
		}
		require.NoError(t, dict.AddVendor(juniperVendor))

		// Create packet with multiline VSA
		pkt := New(CodeAccessAccept, 1)
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
		result := pkt.GetAttributeString("Juniper-User-Permissions")

		expected := JoinMultilineAttribute(permissions)
		assert.Equal(t, expected, result)
		assert.NotContains(t, result, "<contd>")
	})

	t.Run("non-multiline attribute returns first value", func(t *testing.T) {
		dict := dictionary.New()
		require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

		pkt := New(CodeAccessAccept, 1)
		pkt.Dict = dict

		// Add multiple Reply-Message attributes (not marked as multiline)
		pkt.AddAttribute(NewAttribute(18, []byte("First message")))
		pkt.AddAttribute(NewAttribute(18, []byte("Second message")))

		result := pkt.GetAttributeString("Reply-Message")
		assert.Equal(t, "First message", result)
	})

	t.Run("single value multiline attribute", func(t *testing.T) {
		dict := dictionary.New()

		vendor := &dictionary.VendorDefinition{
			ID:   2636,
			Name: "Juniper",
			Attributes: []*dictionary.AttributeDefinition{
				{
					ID:        1,
					Name:      "Juniper-User-Permissions",
					DataType:  dictionary.DataTypeString,
					Multiline: true,
				},
			},
		}
		require.NoError(t, dict.AddVendor(vendor))

		pkt := New(CodeAccessAccept, 1)
		pkt.Dict = dict

		// Single value that fits in one attribute
		singleValue := "access admin shell"
		va := NewVendorAttribute(2636, 1, []byte(singleValue))
		attr := va.ToVSA()
		pkt.AddAttribute(attr)

		result := pkt.GetAttributeString("Juniper-User-Permissions")
		assert.Equal(t, singleValue, result)
	})

	t.Run("attribute not found returns empty string", func(t *testing.T) {
		dict := dictionary.New()
		require.NoError(t, dict.AddStandardAttributes(dictionaries.StandardRFCAttributes))

		pkt := New(CodeAccessAccept, 1)
		pkt.Dict = dict

		result := pkt.GetAttributeString("Non-Existent-Attribute")
		assert.Equal(t, "", result)
	})
}

func TestMessageAuthenticator(t *testing.T) {
	secret := []byte("testing123")

	t.Run("calculate and verify for Access-Request", func(t *testing.T) {
		pkt := New(CodeAccessRequest, 1)
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

		pkt := New(CodeAccessAccept, 1)
		pkt.AddAttribute(NewAttribute(18, []byte("Hello, World!"))) // Reply-Message

		// Add Message-Authenticator
		pkt.AddMessageAuthenticator(secret, reqAuth)

		// Verify it
		assert.True(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("verify fails with wrong secret", func(t *testing.T) {
		pkt := New(CodeAccessRequest, 1)
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
		pkt := New(CodeAccessRequest, 1)
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
		pkt := New(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))

		// No Message-Authenticator added
		assert.False(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("verify fails with invalid length", func(t *testing.T) {
		pkt := New(CodeAccessRequest, 1)
		pkt.AddAttribute(NewAttribute(1, []byte("testuser")))

		// Add Message-Authenticator with wrong length
		pkt.AddAttribute(NewAttribute(80, []byte("short")))

		var reqAuth [16]byte
		copy(reqAuth[:], []byte("1234567890123456"))

		assert.False(t, pkt.VerifyMessageAuthenticator(secret, reqAuth))
	})

	t.Run("calculate with multiple attributes", func(t *testing.T) {
		pkt := New(CodeAccessRequest, 1)
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
