package goradius

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketEncodeDecode(t *testing.T) {
	pkt := NewPacket(CodeAccessRequest, 42)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
	pkt.AddAttribute(NewAttribute(4, EncodeInteger(123)))

	// Set a test authenticator
	for i := range pkt.Authenticator {
		pkt.Authenticator[i] = byte(i)
	}

	data, err := pkt.Encode()
	require.NoError(t, err)

	decoded, err := Decode(data)
	require.NoError(t, err)

	assert.Equal(t, pkt.Code, decoded.Code)
	assert.Equal(t, pkt.Identifier, decoded.Identifier)
	assert.Equal(t, pkt.Length, decoded.Length)
	assert.Equal(t, pkt.Authenticator, decoded.Authenticator)
	assert.Len(t, decoded.Attributes, 2)
}

func BenchmarkPacketEncode(b *testing.B) {
	pkt := NewPacket(CodeAccessRequest, 1)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
	pkt.AddAttribute(NewAttribute(2, []byte("password123")))
	pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = pkt.Encode()
		}
	})
}

func BenchmarkPacketDecode(b *testing.B) {
	pkt := NewPacket(CodeAccessRequest, 1)
	pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
	pkt.AddAttribute(NewAttribute(2, []byte("password123")))
	pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))
	data, _ := pkt.Encode()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = Decode(data)
		}
	})
}

func BenchmarkPacketEncodeDecode(b *testing.B) {
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pkt := NewPacket(CodeAccessRequest, 1)
			pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
			pkt.AddAttribute(NewAttribute(2, []byte("password123")))
			pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

			data, _ := pkt.Encode()
			_, _ = Decode(data)
		}
	})
}

// FuzzDecode ensures the packet parser never panics on arbitrary input and that a
// successfully decoded and re-encoded packet reproduces the original bytes.
func FuzzDecode(f *testing.F) {
	// Valid minimal packet: Access-Request header only.
	minimal := make([]byte, PacketHeaderLength)
	minimal[0] = 1
	minimal[3] = PacketHeaderLength
	f.Add(minimal)

	withAttr := append(append([]byte{}, minimal...), 1, 6, 't', 'e', 's', 't')
	withAttr[3] = byte(len(withAttr))
	f.Add(withAttr)

	f.Add([]byte{})
	f.Add([]byte{1, 0, 0, 19})                                   // shorter than header
	f.Add(append(append([]byte{}, minimal...), 1, 1))            // attribute length < 2
	f.Add(append(append([]byte{}, minimal...), 1, 50, 'x', 'y')) // attribute extends beyond packet

	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := Decode(data)
		if err != nil {
			return
		}

		encoded, err := pkt.Encode()
		if err != nil {
			return // e.g. an invalid code is rejected by IsValid; framing was still parseable
		}
		if !bytes.Equal(encoded, data) {
			t.Fatalf("re-encoded packet differs from input: in=%x out=%x", data, encoded)
		}
	})
}
