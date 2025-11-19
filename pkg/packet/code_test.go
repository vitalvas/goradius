package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vitalvas/goradius/pkg/dictionary"
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

func TestAttributeTypeValidation_RequestOnly(t *testing.T) {
	dict := dictionary.New()

	// Add a request-only attribute
	err := dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{
			ID:       2,
			Name:     "User-Password",
			DataType: dictionary.DataTypeString,
			Type:     dictionary.AttributeTypeRequest,
		},
	})
	assert.NoError(t, err)

	// Test adding to request packet - should succeed and add attribute
	reqPacket := NewWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("User-Password", "secret")
	assert.NoError(t, err, "Should allow request-only attribute in request packet")
	assert.Equal(t, 1, len(reqPacket.Attributes), "Attribute should be added to request packet")

	// Test adding to reply packet - should succeed but silently filter
	replyPacket := NewWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("User-Password", "secret")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(replyPacket.Attributes), "Attribute should be filtered out of reply packet")
}

func TestAttributeTypeValidation_ReplyOnly(t *testing.T) {
	dict := dictionary.New()

	// Add a reply-only attribute
	err := dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{
			ID:       8,
			Name:     "Framed-IP-Address",
			DataType: dictionary.DataTypeIPAddr,
			Type:     dictionary.AttributeTypeReply,
		},
	})
	assert.NoError(t, err)

	// Test adding to reply packet - should succeed and add attribute
	replyPacket := NewWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("Framed-IP-Address", "10.0.0.1")
	assert.NoError(t, err, "Should allow reply-only attribute in reply packet")
	assert.Equal(t, 1, len(replyPacket.Attributes), "Attribute should be added to reply packet")

	// Test adding to request packet - should succeed but silently filter
	reqPacket := NewWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("Framed-IP-Address", "10.0.0.1")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(reqPacket.Attributes), "Attribute should be filtered out of request packet")
}

func TestAttributeTypeValidation_RequestReply(t *testing.T) {
	dict := dictionary.New()

	// Add a request-reply attribute (default)
	err := dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{
			ID:       1,
			Name:     "User-Name",
			DataType: dictionary.DataTypeString,
			Type:     dictionary.AttributeTypeRequestReply,
		},
	})
	assert.NoError(t, err)

	// Test adding to request packet - should succeed
	reqPacket := NewWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("User-Name", "john")
	assert.NoError(t, err, "Should allow request-reply attribute in request packet")

	// Test adding to reply packet - should succeed
	replyPacket := NewWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("User-Name", "john")
	assert.NoError(t, err, "Should allow request-reply attribute in reply packet")
}

func TestAttributeTypeValidation_VendorAttribute(t *testing.T) {
	dict := dictionary.New()

	// Add vendor with request-only and reply-only attributes
	err := dict.AddVendor(&dictionary.VendorDefinition{
		ID:   2636,
		Name: "Juniper",
		Attributes: []*dictionary.AttributeDefinition{
			{
				ID:       10,
				Name:     "Juniper-User-Permissions",
				DataType: dictionary.DataTypeString,
				Type:     dictionary.AttributeTypeRequest,
			},
			{
				ID:       1,
				Name:     "Juniper-Local-User-Name",
				DataType: dictionary.DataTypeString,
				Type:     dictionary.AttributeTypeReply,
			},
		},
	})
	assert.NoError(t, err)

	// Test request-only vendor attribute
	reqPacket := NewWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByName("Juniper-User-Permissions", "admin")
	assert.NoError(t, err, "Should allow request-only vendor attribute in request packet")
	assert.Equal(t, 1, len(reqPacket.Attributes), "Attribute should be added to request packet")

	replyPacket := NewWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByName("Juniper-User-Permissions", "admin")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(replyPacket.Attributes), "Attribute should be filtered out of reply packet")

	// Test reply-only vendor attribute
	replyPacket2 := NewWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket2.AddAttributeByName("Juniper-Local-User-Name", "localuser")
	assert.NoError(t, err, "Should allow reply-only vendor attribute in reply packet")
	assert.Equal(t, 1, len(replyPacket2.Attributes), "Attribute should be added to reply packet")

	reqPacket2 := NewWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket2.AddAttributeByName("Juniper-Local-User-Name", "localuser")
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(reqPacket2.Attributes), "Attribute should be filtered out of request packet")
}

func TestAttributeTypeValidation_WithSecret(t *testing.T) {
	dict := dictionary.New()

	// Add a request-only encrypted attribute
	err := dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{
			ID:         2,
			Name:       "User-Password",
			DataType:   dictionary.DataTypeString,
			Type:       dictionary.AttributeTypeRequest,
			Encryption: dictionary.EncryptionUserPassword,
		},
	})
	assert.NoError(t, err)

	secret := []byte("secret")
	var auth [16]byte

	// Test with request packet - should succeed and add attribute
	reqPacket := NewWithDictionary(CodeAccessRequest, 1, dict)
	err = reqPacket.AddAttributeByNameWithSecret("User-Password", "password", secret, auth)
	assert.NoError(t, err, "Should allow request-only attribute in request packet")
	assert.Equal(t, 1, len(reqPacket.Attributes), "Attribute should be added to request packet")

	// Test with reply packet - should succeed but silently filter
	replyPacket := NewWithDictionary(CodeAccessAccept, 1, dict)
	err = replyPacket.AddAttributeByNameWithSecret("User-Password", "password", secret, auth)
	assert.NoError(t, err, "Should not return error for filtered attribute")
	assert.Equal(t, 0, len(replyPacket.Attributes), "Attribute should be filtered out of reply packet")
}

func TestAttributeTypeValidation_AllPacketTypes(t *testing.T) {
	dict := dictionary.New()

	// Add request-only, reply-only, and request-reply attributes
	err := dict.AddStandardAttributes([]*dictionary.AttributeDefinition{
		{
			ID:       1,
			Name:     "User-Name",
			DataType: dictionary.DataTypeString,
			Type:     dictionary.AttributeTypeRequestReply,
		},
		{
			ID:       2,
			Name:     "User-Password",
			DataType: dictionary.DataTypeString,
			Type:     dictionary.AttributeTypeRequest,
		},
		{
			ID:       8,
			Name:     "Framed-IP-Address",
			DataType: dictionary.DataTypeIPAddr,
			Type:     dictionary.AttributeTypeReply,
		},
	})
	assert.NoError(t, err)

	requestCodes := []Code{
		CodeAccessRequest,
		CodeAccountingRequest,
		CodeStatusServer,
		CodeDisconnectRequest,
		CodeCoARequest,
	}

	replyCodes := []Code{
		CodeAccessAccept,
		CodeAccessReject,
		CodeAccessChallenge,
		CodeAccountingResponse,
		CodeStatusClient,
		CodeDisconnectACK,
		CodeDisconnectNAK,
		CodeCoAACK,
		CodeCoANAK,
	}

	// Test request-only attribute across all packet types
	for _, code := range requestCodes {
		t.Run("Request-only_in_"+code.String(), func(t *testing.T) {
			p := NewWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("User-Password", "secret")
			assert.NoError(t, err)
			assert.Equal(t, 1, len(p.Attributes), "Should add attribute in request packet")
		})
	}

	for _, code := range replyCodes {
		t.Run("Request-only_in_"+code.String(), func(t *testing.T) {
			p := NewWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("User-Password", "secret")
			assert.NoError(t, err)
			assert.Equal(t, 0, len(p.Attributes), "Should filter attribute in reply packet")
		})
	}

	// Test reply-only attribute across all packet types
	for _, code := range requestCodes {
		t.Run("Reply-only_in_"+code.String(), func(t *testing.T) {
			p := NewWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("Framed-IP-Address", "10.0.0.1")
			assert.NoError(t, err)
			assert.Equal(t, 0, len(p.Attributes), "Should filter attribute in request packet")
		})
	}

	for _, code := range replyCodes {
		t.Run("Reply-only_in_"+code.String(), func(t *testing.T) {
			p := NewWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("Framed-IP-Address", "10.0.0.1")
			assert.NoError(t, err)
			assert.Equal(t, 1, len(p.Attributes), "Should add attribute in reply packet")
		})
	}

	// Test request-reply attribute across all packet types - should work everywhere
	allCodes := make([]Code, 0, len(requestCodes)+len(replyCodes))
	allCodes = append(allCodes, requestCodes...)
	allCodes = append(allCodes, replyCodes...)
	for _, code := range allCodes {
		t.Run("Request-reply_in_"+code.String(), func(t *testing.T) {
			p := NewWithDictionary(code, 1, dict)
			err := p.AddAttributeByName("User-Name", "john")
			assert.NoError(t, err)
		})
	}
}
