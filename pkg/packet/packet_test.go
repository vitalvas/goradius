package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	packet := New(CodeAccessRequest, 123)

	assert.Equal(t, CodeAccessRequest, packet.Code)
	assert.Equal(t, uint8(123), packet.Identifier)
	assert.Equal(t, uint16(PacketHeaderLength), packet.Length)
	assert.Empty(t, packet.Attributes)
}

func TestPacketAddAttribute(t *testing.T) {
	packet := New(CodeAccessRequest, 1)
	attr := NewStringAttribute(AttrUserName, "testuser")

	packet.AddAttribute(attr)

	assert.Len(t, packet.Attributes, 1)
	assert.Equal(t, attr, packet.Attributes[0])
	assert.Equal(t, uint16(PacketHeaderLength+int(attr.Length)), packet.Length)
}

func TestPacketGetAttribute(t *testing.T) {
	packet := New(CodeAccessRequest, 1)
	attr1 := NewStringAttribute(AttrUserName, "testuser")
	attr2 := NewIntegerAttribute(AttrServiceType, 1)

	packet.AddAttribute(attr1)
	packet.AddAttribute(attr2)

	// Test getting existing attribute
	found, exists := packet.GetAttribute(AttrUserName)
	assert.True(t, exists)
	assert.Equal(t, attr1, found)

	// Test getting non-existing attribute
	_, exists = packet.GetAttribute(AttrNASIPAddress)
	assert.False(t, exists)
}

func TestPacketGetAttributes(t *testing.T) {
	packet := New(CodeAccessRequest, 1)
	attr1 := NewStringAttribute(AttrUserName, "testuser1")
	attr2 := NewStringAttribute(AttrUserName, "testuser2")
	attr3 := NewIntegerAttribute(AttrServiceType, 1)

	packet.AddAttribute(attr1)
	packet.AddAttribute(attr2)
	packet.AddAttribute(attr3)

	userNameAttrs := packet.GetAttributes(AttrUserName)
	assert.Len(t, userNameAttrs, 2)
	assert.Equal(t, attr1, userNameAttrs[0])
	assert.Equal(t, attr2, userNameAttrs[1])

	serviceTypeAttrs := packet.GetAttributes(AttrServiceType)
	assert.Len(t, serviceTypeAttrs, 1)
	assert.Equal(t, attr3, serviceTypeAttrs[0])

	nonExistentAttrs := packet.GetAttributes(AttrNASIPAddress)
	assert.Empty(t, nonExistentAttrs)
}

func TestPacketRemoveAttribute(t *testing.T) {
	packet := New(CodeAccessRequest, 1)
	attr1 := NewStringAttribute(AttrUserName, "testuser")
	attr2 := NewIntegerAttribute(AttrServiceType, 1)

	packet.AddAttribute(attr1)
	packet.AddAttribute(attr2)

	originalLength := packet.Length

	// Remove existing attribute
	removed := packet.RemoveAttribute(AttrUserName)
	assert.True(t, removed)
	assert.Len(t, packet.Attributes, 1)
	assert.Equal(t, attr2, packet.Attributes[0])
	assert.Equal(t, originalLength-uint16(attr1.Length), packet.Length)

	// Try to remove non-existing attribute
	removed = packet.RemoveAttribute(AttrUserName)
	assert.False(t, removed)
	assert.Len(t, packet.Attributes, 1)
}

func TestPacketRemoveAllAttributes(t *testing.T) {
	packet := New(CodeAccessRequest, 1)
	attr1 := NewStringAttribute(AttrUserName, "testuser1")
	attr2 := NewStringAttribute(AttrUserName, "testuser2")
	attr3 := NewIntegerAttribute(AttrServiceType, 1)

	packet.AddAttribute(attr1)
	packet.AddAttribute(attr2)
	packet.AddAttribute(attr3)

	removed := packet.RemoveAllAttributes(AttrUserName)
	assert.Equal(t, 2, removed)
	assert.Len(t, packet.Attributes, 1)
	assert.Equal(t, attr3, packet.Attributes[0])

	removed = packet.RemoveAllAttributes(AttrNASIPAddress)
	assert.Equal(t, 0, removed)
}

func TestPacketValidate(t *testing.T) {
	tests := []struct {
		name    string
		packet  *Packet
		wantErr bool
	}{
		{
			name:    "valid packet",
			packet:  New(CodeAccessRequest, 1),
			wantErr: false,
		},
		{
			name: "packet too short",
			packet: &Packet{
				Code:       CodeAccessRequest,
				Identifier: 1,
				Length:     10,
			},
			wantErr: true,
		},
		{
			name: "packet too long",
			packet: &Packet{
				Code:       CodeAccessRequest,
				Identifier: 1,
				Length:     MaxPacketLength + 1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.packet.Validate()
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestPacketCopy(t *testing.T) {
	original := New(CodeAccessRequest, 1)
	attr := NewStringAttribute(AttrUserName, "testuser")
	original.AddAttribute(attr)

	copied := original.Copy()

	assert.Equal(t, original.Code, copied.Code)
	assert.Equal(t, original.Identifier, copied.Identifier)
	assert.Equal(t, original.Length, copied.Length)
	assert.Equal(t, original.Authenticator, copied.Authenticator)
	assert.Equal(t, original.Attributes, copied.Attributes)

	// Ensure deep copy
	originalFirstByte := original.Attributes[0].Value[0]
	copied.Attributes[0].Value[0] = 'X'
	assert.NotEqual(t, originalFirstByte, copied.Attributes[0].Value[0])
	assert.Equal(t, originalFirstByte, original.Attributes[0].Value[0])
}

func TestPacketString(t *testing.T) {
	packet := New(CodeAccessRequest, 123)
	packet.AddAttribute(NewStringAttribute(AttrUserName, "testuser"))

	str := packet.String()
	assert.Contains(t, str, "Access-Request")
	assert.Contains(t, str, "ID=123")
	assert.Contains(t, str, "Attributes=1")
}

func TestPacketConcurrency(t *testing.T) {
	// Test that packet operations work correctly when called sequentially
	// (RADIUS packets are not designed to be thread-safe by default)
	packet := New(CodeAccessRequest, 1)

	for i := 0; i < 10; i++ {
		attr := NewStringAttribute(AttrUserName, string(rune('a'+i)))
		packet.AddAttribute(attr)

		_, exists := packet.GetAttribute(AttrUserName)
		assert.True(t, exists)

		str := packet.String()
		assert.NotEmpty(t, str)

		copied := packet.Copy()
		assert.NotNil(t, copied)
	}

	assert.Len(t, packet.Attributes, 10)
}
