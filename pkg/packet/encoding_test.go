package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPacketEncodeDecode(t *testing.T) {
	pkt := New(CodeAccessRequest, 42)
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
	pkt := New(CodeAccessRequest, 1)
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
	pkt := New(CodeAccessRequest, 1)
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
			pkt := New(CodeAccessRequest, 1)
			pkt.AddAttribute(NewAttribute(1, []byte("testuser")))
			pkt.AddAttribute(NewAttribute(2, []byte("password123")))
			pkt.AddAttribute(NewAttribute(4, []byte{192, 168, 1, 1}))

			data, _ := pkt.Encode()
			_, _ = Decode(data)
		}
	})
}
