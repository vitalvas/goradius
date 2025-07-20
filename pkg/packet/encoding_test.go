package packet

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketEncode(t *testing.T) {
	packet := New(CodeAccessRequest, 123)
	packet.Authenticator = [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	packet.AddAttribute(NewStringAttribute(AttrUserName, "test"))

	data, err := packet.Encode()
	require.NoError(t, err)

	assert.Equal(t, int(packet.Length), len(data))
	assert.Equal(t, byte(CodeAccessRequest), data[0])
	assert.Equal(t, byte(123), data[1])
	assert.Equal(t, packet.Length, uint16(data[2])<<8|uint16(data[3]))

	// Check authenticator
	for i := 0; i < 16; i++ {
		assert.Equal(t, packet.Authenticator[i], data[4+i])
	}

	// Check attribute
	assert.Equal(t, AttrUserName, data[20])
	assert.Equal(t, byte(6), data[21]) // 2 + 4 bytes
	assert.Equal(t, []byte("test"), data[22:26])
}

func TestPacketDecode(t *testing.T) {
	// Create test packet data
	data := []byte{
		1,     // Code: Access-Request
		123,   // Identifier
		0, 26, // Length: 26 bytes
		// Authenticator (16 bytes)
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
		// Attribute: User-Name = "test"
		1,                  // Type: User-Name
		6,                  // Length: 6 bytes
		't', 'e', 's', 't', // Value: "test"
	}

	packet, err := Decode(data)
	require.NoError(t, err)

	assert.Equal(t, CodeAccessRequest, packet.Code)
	assert.Equal(t, uint8(123), packet.Identifier)
	assert.Equal(t, uint16(26), packet.Length)

	expectedAuth := [16]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	assert.Equal(t, expectedAuth, packet.Authenticator)

	require.Len(t, packet.Attributes, 1)
	assert.Equal(t, AttrUserName, packet.Attributes[0].Type)
	assert.Equal(t, "test", packet.Attributes[0].GetString())
}

func TestPacketDecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{1, 2, 3},
		},
		{
			name: "invalid code",
			data: make([]byte, 20),
		},
		{
			name: "invalid length - too small",
			data: []byte{1, 123, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
		{
			name: "invalid length - too large",
			data: append([]byte{1, 123, 0xFF, 0xFF}, make([]byte, 16)...),
		},
		{
			name: "data shorter than packet length",
			data: []byte{1, 123, 0, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Decode(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestPacketDecodeFromReader(t *testing.T) {
	// Create test packet
	packet := New(CodeAccessRequest, 1)
	packet.AddAttribute(NewStringAttribute(AttrUserName, "testuser"))

	data, err := packet.Encode()
	require.NoError(t, err)

	reader := bytes.NewReader(data)
	decodedPacket, err := DecodeFromReader(reader)
	require.NoError(t, err)

	assert.Equal(t, packet.Code, decodedPacket.Code)
	assert.Equal(t, packet.Identifier, decodedPacket.Identifier)
	assert.Equal(t, packet.Length, decodedPacket.Length)
	assert.Len(t, decodedPacket.Attributes, 1)
	assert.Equal(t, "testuser", decodedPacket.Attributes[0].GetString())
}

func TestAttributeEncode(t *testing.T) {
	attr := NewStringAttribute(AttrUserName, "test")

	data, err := attr.Encode()
	require.NoError(t, err)

	expected := []byte{
		1,                  // Type: User-Name
		6,                  // Length: 6 bytes
		't', 'e', 's', 't', // Value: "test"
	}

	assert.Equal(t, expected, data)
}

func TestDecodeAttribute(t *testing.T) {
	data := []byte{
		1,                  // Type: User-Name
		6,                  // Length: 6 bytes
		't', 'e', 's', 't', // Value: "test"
	}

	attr, bytesRead, err := DecodeAttribute(data)
	require.NoError(t, err)

	assert.Equal(t, AttrUserName, attr.Type)
	assert.Equal(t, uint8(6), attr.Length)
	assert.Equal(t, "test", attr.GetString())
	assert.Equal(t, 6, bytesRead)
}

func TestDecodeAttributeErrors(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "too short",
			data: []byte{1},
		},
		{
			name: "invalid length",
			data: []byte{1, 1},
		},
		{
			name: "data too short for length",
			data: []byte{1, 10, 't', 'e'},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := DecodeAttribute(tt.data)
			assert.Error(t, err)
		})
	}
}

func TestPacketWriteTo(t *testing.T) {
	packet := New(CodeAccessRequest, 1)
	packet.AddAttribute(NewStringAttribute(AttrUserName, "test"))

	var buf bytes.Buffer
	n, err := packet.WriteTo(&buf)
	require.NoError(t, err)

	assert.Equal(t, int64(packet.Length), n)
	assert.Equal(t, int(packet.Length), buf.Len())

	// Verify we can decode what we wrote
	decodedPacket, err := Decode(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, packet.Code, decodedPacket.Code)
	assert.Equal(t, packet.Identifier, decodedPacket.Identifier)
}

func TestEncodeDecode_Roundtrip(t *testing.T) {
	original := New(CodeAccessRequest, 42)
	original.Authenticator = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	original.AddAttribute(NewStringAttribute(AttrUserName, "testuser"))
	original.AddAttribute(NewIntegerAttribute(AttrServiceType, 1))
	original.AddAttribute(NewIPAddressAttribute(AttrNASIPAddress, [4]byte{192, 168, 1, 1}))

	// Encode
	data, err := original.Encode()
	require.NoError(t, err)

	// Decode
	decoded, err := Decode(data)
	require.NoError(t, err)

	// Compare
	assert.Equal(t, original.Code, decoded.Code)
	assert.Equal(t, original.Identifier, decoded.Identifier)
	assert.Equal(t, original.Length, decoded.Length)
	assert.Equal(t, original.Authenticator, decoded.Authenticator)
	assert.Equal(t, len(original.Attributes), len(decoded.Attributes))

	for i, attr := range original.Attributes {
		assert.Equal(t, attr.Type, decoded.Attributes[i].Type)
		assert.Equal(t, attr.Length, decoded.Attributes[i].Length)
		assert.Equal(t, attr.Value, decoded.Attributes[i].Value)
	}
}

func TestPacketEncodingMultiple(t *testing.T) {
	packet := New(CodeAccessRequest, 1)
	packet.AddAttribute(NewStringAttribute(AttrUserName, "testuser"))

	// Test multiple encode/decode operations work correctly
	for i := 0; i < 10; i++ {
		data, err := packet.Encode()
		assert.NoError(t, err)
		assert.NotEmpty(t, data)

		decoded, err := Decode(data)
		assert.NoError(t, err)
		assert.Equal(t, packet.Code, decoded.Code)
		assert.Equal(t, packet.Identifier, decoded.Identifier)
		assert.Equal(t, packet.Length, decoded.Length)
	}
}
