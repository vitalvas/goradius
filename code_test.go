package goradius

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeIsRequest(t *testing.T) {
	tests := []struct {
		code     Code
		expected bool
	}{
		{CodeAccessRequest, true},
		{CodeAccountingRequest, true},
		{CodeStatusServer, true},
		{CodeDisconnectRequest, true},
		{CodeCoARequest, true},
		{CodeAccessAccept, false},
		{CodeAccessReject, false},
		{CodeAccessChallenge, false},
		{CodeAccountingResponse, false},
		{CodeStatusClient, false},
		{CodeDisconnectACK, false},
		{CodeDisconnectNAK, false},
		{CodeCoAACK, false},
		{CodeCoANAK, false},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.IsRequest())
		})
	}
}

func TestCodeIsReply(t *testing.T) {
	tests := []struct {
		code     Code
		expected bool
	}{
		{CodeAccessRequest, false},
		{CodeAccountingRequest, false},
		{CodeStatusServer, false},
		{CodeDisconnectRequest, false},
		{CodeCoARequest, false},
		{CodeAccessAccept, true},
		{CodeAccessReject, true},
		{CodeAccessChallenge, true},
		{CodeAccountingResponse, true},
		{CodeStatusClient, true},
		{CodeDisconnectACK, true},
		{CodeDisconnectNAK, true},
		{CodeCoAACK, true},
		{CodeCoANAK, true},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.IsReply())
		})
	}
}

func TestAttributeUsageValidation_RequestOnly(t *testing.T) {
	dict := NewDictionary()

	// Add a request-only attribute
	err := dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       2,
			Name:     "user-password",
			DataType: DataTypeString,
			Usage:    UsageAllRequests,
		},
	})
	assert.NoError(t, err)

	// Test adding to request packet - should succeed and add attribute
	reqPacket := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("user-password", "secret")
	assert.NoError(t, err, "Should allow request-only attribute in request packet")
	assert.Equal(t, 1, len(reqPacket.Attributes), "Attribute should be added to request packet")

	// Test adding to reply packet - should succeed but silently filter
	replyPacket := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("user-password", "secret")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(replyPacket.Attributes), "Attribute should be filtered out of reply packet")
}

func TestAttributeUsageValidation_ReplyOnly(t *testing.T) {
	dict := NewDictionary()

	// Add a reply-only attribute
	err := dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       8,
			Name:     "framed-ip-address",
			DataType: DataTypeIPAddr,
			Usage:    UsageAllResponses,
		},
	})
	assert.NoError(t, err)

	// Test adding to reply packet - should succeed and add attribute
	replyPacket := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("framed-ip-address", "10.0.0.1")
	assert.NoError(t, err, "Should allow reply-only attribute in reply packet")
	assert.Equal(t, 1, len(replyPacket.Attributes), "Attribute should be added to reply packet")

	// Test adding to request packet - should succeed but silently filter
	reqPacket := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("framed-ip-address", "10.0.0.1")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(reqPacket.Attributes), "Attribute should be filtered out of request packet")
}

func TestAttributeUsageValidation_RequestReply(t *testing.T) {
	dict := NewDictionary()

	// Add a request-reply attribute (default)
	err := dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       1,
			Name:     "user-name",
			DataType: DataTypeString,
		},
	})
	assert.NoError(t, err)

	// Test adding to request packet - should succeed
	reqPacket := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("user-name", "john")
	assert.NoError(t, err, "Should allow request-reply attribute in request packet")

	// Test adding to reply packet - should succeed
	replyPacket := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("user-name", "john")
	assert.NoError(t, err, "Should allow request-reply attribute in reply packet")
}

func TestAttributeUsageValidation_VendorAttribute(t *testing.T) {
	dict := NewDictionary()

	// Add vendor with request-only and reply-only attributes
	err := dict.AddVendor(&VendorDefinition{
		ID:   2636,
		Name: "juniper",
		Attributes: []*AttributeDefinition{
			{
				ID:       10,
				Name:     "juniper-user-permissions",
				DataType: DataTypeString,
				Usage:    UsageAllRequests,
			},
			{
				ID:       1,
				Name:     "juniper-local-user-name",
				DataType: DataTypeString,
				Usage:    UsageAllResponses,
			},
		},
	})
	assert.NoError(t, err)

	// Test request-only vendor attribute
	reqPacket := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("juniper-user-permissions", "admin")
	assert.NoError(t, err, "Should allow request-only vendor attribute in request packet")
	assert.Equal(t, 1, len(reqPacket.Attributes), "Attribute should be added to request packet")

	replyPacket := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("juniper-user-permissions", "admin")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(replyPacket.Attributes), "Attribute should be filtered out of reply packet")

	// Test reply-only vendor attribute
	replyPacket2 := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket2.AddAttributeByName("juniper-local-user-name", "localuser")
	assert.NoError(t, err, "Should allow reply-only vendor attribute in reply packet")
	assert.Equal(t, 1, len(replyPacket2.Attributes), "Attribute should be added to reply packet")

	reqPacket2 := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket2.AddAttributeByName("juniper-local-user-name", "localuser")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(reqPacket2.Attributes), "Attribute should be filtered out of request packet")
}

func TestAttributeUsageValidation_WithSecret(t *testing.T) {
	dict := NewDictionary()

	// Add a request-only encrypted attribute
	err := dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:         2,
			Name:       "user-password",
			DataType:   DataTypeString,
			Usage:      UsageAllRequests,
			Encryption: EncryptionUserPassword,
		},
	})
	assert.NoError(t, err)

	secret := []byte("secret")

	// Test with request packet - should succeed and add attribute
	reqPacket := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
	reqPacket.Secret = secret
	err = reqPacket.AddAttributeByName("user-password", "password")
	assert.NoError(t, err, "Should allow request-only attribute in request packet")
	assert.Equal(t, 1, len(reqPacket.Attributes), "Attribute should be added to request packet")

	// Test with reply packet - should succeed but silently filter
	replyPacket := NewPacketWithDictionary(CodeAccessAccept, 1, dict)
	replyPacket.Secret = secret
	err = replyPacket.AddAttributeByName("user-password", "password")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(replyPacket.Attributes), "Attribute should be filtered out of reply packet")
}

func TestAttributeUsageValidation_AllPacketTypes(t *testing.T) {
	dict := NewDictionary()

	// Add request-only, reply-only, and request-reply attributes
	err := dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       1,
			Name:     "user-name",
			DataType: DataTypeString,
		},
		{
			ID:       2,
			Name:     "user-password",
			DataType: DataTypeString,
			Usage:    UsageAllRequests,
		},
		{
			ID:       8,
			Name:     "framed-ip-address",
			DataType: DataTypeIPAddr,
			Usage:    UsageAllResponses,
		},
	})
	assert.NoError(t, err)

	requestCodes := []Code{
		CodeAccessRequest,
		CodeAccountingRequest,
		CodeDisconnectRequest,
		CodeCoARequest,
	}

	replyCodes := []Code{
		CodeAccessAccept,
		CodeAccessReject,
		CodeAccessChallenge,
		CodeAccountingResponse,
		CodeDisconnectACK,
		CodeDisconnectNAK,
		CodeCoAACK,
		CodeCoANAK,
	}

	// Test request-only attribute across all packet types
	for _, code := range requestCodes {
		t.Run(fmt.Sprintf("Request-only_in_%s", code.String()), func(t *testing.T) {
			p := NewPacketWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("user-password", "secret")
			assert.NoError(t, err)
			assert.Equal(t, 1, len(p.Attributes), "Should add attribute in request packet")
		})
	}

	for _, code := range replyCodes {
		t.Run(fmt.Sprintf("Request-only_in_%s", code.String()), func(t *testing.T) {
			p := NewPacketWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("user-password", "secret")
			assert.NoError(t, err)
			assert.Equal(t, 0, len(p.Attributes), "Should filter attribute in reply packet")
		})
	}

	// Test reply-only attribute across all packet types
	for _, code := range requestCodes {
		t.Run(fmt.Sprintf("Reply-only_in_%s", code.String()), func(t *testing.T) {
			p := NewPacketWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("framed-ip-address", "10.0.0.1")
			assert.NoError(t, err)
			assert.Equal(t, 0, len(p.Attributes), "Should filter attribute in request packet")
		})
	}

	for _, code := range replyCodes {
		t.Run(fmt.Sprintf("Reply-only_in_%s", code.String()), func(t *testing.T) {
			p := NewPacketWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("framed-ip-address", "10.0.0.1")
			assert.NoError(t, err)
			assert.Equal(t, 1, len(p.Attributes), "Should add attribute in reply packet")
		})
	}

	// Test request-reply attribute across all packet types - should work everywhere
	allCodes := make([]Code, 0, len(requestCodes)+len(replyCodes))
	allCodes = append(allCodes, requestCodes...)
	allCodes = append(allCodes, replyCodes...)
	for _, code := range allCodes {
		t.Run(fmt.Sprintf("Request-reply_in_%s", code.String()), func(t *testing.T) {
			p := NewPacketWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("user-name", "john")
			assert.NoError(t, err)
		})
	}
}

func TestCodeString(t *testing.T) {
	tests := []struct {
		code Code
		want string
	}{
		{CodeAccessRequest, "access-request"},
		{CodeAccessAccept, "access-accept"},
		{CodeAccessReject, "access-reject"},
		{CodeAccountingRequest, "accounting-request"},
		{CodeAccountingResponse, "accounting-response"},
		{CodeAccessChallenge, "access-challenge"},
		{CodeStatusServer, "status-server"},
		{CodeStatusClient, "status-client"},
		{CodeDisconnectRequest, "disconnect-request"},
		{CodeDisconnectACK, "disconnect-ack"},
		{CodeDisconnectNAK, "disconnect-nak"},
		{CodeCoARequest, "coa-request"},
		{CodeCoAACK, "coa-ack"},
		{CodeCoANAK, "coa-nak"},
		{Code(0), "unknown"},
		{Code(255), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.code.String())
		})
	}
}

func TestCodeByName(t *testing.T) {
	t.Run("round trips every valid code", func(t *testing.T) {
		valid := 0
		for i := range 256 {
			c := Code(i)
			if !c.IsValid() {
				continue
			}
			valid++
			got, ok := CodeByName[c.String()]
			assert.True(t, ok, c.String())
			assert.Equal(t, c, got)
		}
		assert.Len(t, CodeByName, valid)
	})

	t.Run("lookups", func(t *testing.T) {
		tests := []struct {
			name   string
			want   Code
			wantOK bool
		}{
			{"access-request", CodeAccessRequest, true},
			{"coa-nak", CodeCoANAK, true},
			{"unknown", 0, false},
			{"Access-Request", 0, false},
			{"", 0, false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got, ok := CodeByName[tt.name]
				assert.Equal(t, tt.wantOK, ok)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

func FuzzCodeByName(f *testing.F) {
	f.Add("access-request")
	f.Add("Access-Request")

	f.Fuzz(func(t *testing.T, name string) {
		if c, ok := CodeByName[name]; ok {
			assert.Equal(t, name, c.String())
		}
	})
}

func BenchmarkCodeByName(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = CodeByName["accounting-request"]
	}
}

func FuzzCodeString(f *testing.F) {
	f.Add(uint8(CodeAccessRequest))
	f.Add(uint8(0))

	f.Fuzz(func(t *testing.T, c uint8) {
		s := Code(c).String()
		assert.Equal(t, strings.ToLower(s), s)
		assert.Equal(t, Code(c).IsValid(), s != "unknown")
	})
}

func BenchmarkCodeString(b *testing.B) {
	codes := []Code{
		CodeAccessRequest,
		CodeAccessAccept,
		CodeAccountingRequest,
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, c := range codes {
			_ = c.String()
		}
	}
}

func BenchmarkCodeIsValid(b *testing.B) {
	codes := []Code{
		CodeAccessRequest,
		CodeAccessAccept,
		Code(99),
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, c := range codes {
			_ = c.IsValid()
		}
	}
}

func BenchmarkCodeIsRequest(b *testing.B) {
	codes := []Code{
		CodeAccessRequest,
		CodeAccessAccept,
		CodeAccountingRequest,
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, c := range codes {
			_ = c.IsRequest()
		}
	}
}

func BenchmarkCodeIsReply(b *testing.B) {
	codes := []Code{
		CodeAccessRequest,
		CodeAccessAccept,
		CodeAccountingResponse,
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, c := range codes {
			_ = c.IsReply()
		}
	}
}
