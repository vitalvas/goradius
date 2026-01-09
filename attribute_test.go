package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewAttribute(t *testing.T) {
	value := []byte("testvalue")
	attr := NewAttribute(1, value)

	assert.Equal(t, uint8(1), attr.Type)
	assert.Equal(t, uint8(len(value)+AttributeHeaderLength), attr.Length)
	assert.Equal(t, value, attr.Value)
	assert.Equal(t, uint8(0), attr.Tag)
}

func TestNewTaggedAttribute(t *testing.T) {
	value := []byte("testvalue")
	tag := uint8(5)
	attr := NewTaggedAttribute(64, tag, value)

	assert.Equal(t, uint8(64), attr.Type)
	assert.Equal(t, uint8(len(value)+1+AttributeHeaderLength), attr.Length)
	assert.Equal(t, tag, attr.Tag)
	assert.Equal(t, value, attr.GetValue())
	assert.Equal(t, tag, attr.Value[0]) // Tag is first byte
}

func TestAttributeGetValue(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *Attribute
		expected []byte
	}{
		{
			name: "regular attribute",
			setup: func() *Attribute {
				return NewAttribute(1, []byte("test"))
			},
			expected: []byte("test"),
		},
		{
			name: "tagged attribute",
			setup: func() *Attribute {
				return NewTaggedAttribute(64, 5, []byte("test"))
			},
			expected: []byte("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := tt.setup()
			assert.Equal(t, tt.expected, attr.GetValue())
		})
	}
}

func TestAttributeString(t *testing.T) {
	tests := []struct {
		name     string
		attr     *Attribute
		contains []string
	}{
		{
			name:     "regular attribute",
			attr:     NewAttribute(1, []byte("test")),
			contains: []string{"Type=1", "Length="},
		},
		{
			name:     "tagged attribute",
			attr:     NewTaggedAttribute(64, 5, []byte("test")),
			contains: []string{"Type=64", "Tag=5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.attr.String()
			for _, substr := range tt.contains {
				assert.Contains(t, str, substr)
			}
		})
	}
}

func TestNewVendorAttribute(t *testing.T) {
	vendorID := uint32(4874)
	vendorType := uint8(13)
	value := []byte("testvalue")

	va := NewVendorAttribute(vendorID, vendorType, value)

	assert.Equal(t, vendorID, va.VendorID)
	assert.Equal(t, vendorType, va.VendorType)
	assert.Equal(t, value, va.Value)
	assert.Equal(t, uint8(0), va.Tag)
}

func TestNewTaggedVendorAttribute(t *testing.T) {
	vendorID := uint32(4874)
	vendorType := uint8(1)
	tag := uint8(3)
	value := []byte("testvalue")

	va := NewTaggedVendorAttribute(vendorID, vendorType, tag, value)

	assert.Equal(t, vendorID, va.VendorID)
	assert.Equal(t, vendorType, va.VendorType)
	assert.Equal(t, tag, va.Tag)
	assert.Equal(t, value, va.GetValue())
	assert.Equal(t, tag, va.Value[0])
}

func TestVendorAttributeGetValue(t *testing.T) {
	tests := []struct {
		name     string
		setup    func() *VendorAttribute
		expected []byte
	}{
		{
			name: "regular vendor attribute",
			setup: func() *VendorAttribute {
				return NewVendorAttribute(4874, 13, []byte("test"))
			},
			expected: []byte("test"),
		},
		{
			name: "tagged vendor attribute",
			setup: func() *VendorAttribute {
				return NewTaggedVendorAttribute(4874, 1, 3, []byte("test"))
			},
			expected: []byte("test"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			va := tt.setup()
			assert.Equal(t, tt.expected, va.GetValue())
		})
	}
}

func TestVendorAttributeString(t *testing.T) {
	tests := []struct {
		name     string
		va       *VendorAttribute
		contains []string
	}{
		{
			name:     "regular vendor attribute",
			va:       NewVendorAttribute(4874, 13, []byte("test")),
			contains: []string{"VendorID=4874", "Type=13"},
		},
		{
			name:     "tagged vendor attribute",
			va:       NewTaggedVendorAttribute(4874, 1, 3, []byte("test")),
			contains: []string{"VendorID=4874", "Type=1", "Tag=3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			str := tt.va.String()
			for _, substr := range tt.contains {
				assert.Contains(t, str, substr)
			}
		})
	}
}

func TestVendorAttributeToVSA(t *testing.T) {
	va := NewVendorAttribute(4874, 13, []byte("8.8.8.8"))
	attr := va.ToVSA()

	assert.Equal(t, uint8(26), attr.Type) // Vendor-Specific type

	// Parse it back
	parsedVA, err := ParseVSA(attr)
	require.NoError(t, err)
	assert.Equal(t, va.VendorID, parsedVA.VendorID)
	assert.Equal(t, va.VendorType, parsedVA.VendorType)
	assert.Equal(t, va.Value, parsedVA.Value)
}

func TestParseVSA(t *testing.T) {
	tests := []struct {
		name    string
		setup   func() *Attribute
		wantErr bool
		check   func(*testing.T, *VendorAttribute)
	}{
		{
			name: "valid VSA",
			setup: func() *Attribute {
				va := NewVendorAttribute(4874, 13, []byte("test"))
				return va.ToVSA()
			},
			wantErr: false,
			check: func(t *testing.T, va *VendorAttribute) {
				assert.Equal(t, uint32(4874), va.VendorID)
				assert.Equal(t, uint8(13), va.VendorType)
				assert.Equal(t, []byte("test"), va.Value)
			},
		},
		{
			name: "tagged VSA",
			setup: func() *Attribute {
				va := NewTaggedVendorAttribute(4874, 1, 5, []byte("test"))
				return va.ToVSA()
			},
			wantErr: false,
			check: func(t *testing.T, va *VendorAttribute) {
				assert.Equal(t, uint32(4874), va.VendorID)
				assert.Equal(t, uint8(1), va.VendorType)
				assert.Equal(t, uint8(5), va.Tag)
			},
		},
		{
			name: "non-VSA attribute",
			setup: func() *Attribute {
				return NewAttribute(1, []byte("test"))
			},
			wantErr: true,
		},
		{
			name: "VSA too short",
			setup: func() *Attribute {
				return &Attribute{
					Type:   26,
					Length: 5,
					Value:  []byte{1, 2, 3},
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attr := tt.setup()
			va, err := ParseVSA(attr)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				if tt.check != nil {
					tt.check(t, va)
				}
			}
		})
	}
}

func TestVSARoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		vendorID uint32
		typeID   uint8
		value    []byte
	}{
		{"simple", 9, 1, []byte("test")},
		{"long value", 4874, 13, []byte("this is a longer value with more data")},
		{"empty value", 123, 5, []byte{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create VSA
			va := NewVendorAttribute(tt.vendorID, tt.typeID, tt.value)

			// Convert to attribute
			attr := va.ToVSA()

			// Parse back
			parsed, err := ParseVSA(attr)
			require.NoError(t, err)

			// Verify
			assert.Equal(t, tt.vendorID, parsed.VendorID)
			assert.Equal(t, tt.typeID, parsed.VendorType)
			assert.Equal(t, tt.value, parsed.Value)
		})
	}
}

func BenchmarkNewAttribute(b *testing.B) {
	value := []byte("testvalue")
	b.ReportAllocs()
	for b.Loop() {
		_ = NewAttribute(1, value)
	}
}

func BenchmarkNewTaggedAttribute(b *testing.B) {
	value := []byte("testvalue")
	b.ReportAllocs()
	for b.Loop() {
		_ = NewTaggedAttribute(64, 5, value)
	}
}

func BenchmarkNewVendorAttribute(b *testing.B) {
	value := []byte("testvalue")
	b.ReportAllocs()
	for b.Loop() {
		_ = NewVendorAttribute(4874, 13, value)
	}
}

func BenchmarkNewTaggedVendorAttribute(b *testing.B) {
	value := []byte("testvalue")
	b.ReportAllocs()
	for b.Loop() {
		_ = NewTaggedVendorAttribute(4874, 1, 3, value)
	}
}

func BenchmarkAttributeGetValue(b *testing.B) {
	b.Run("regular", func(b *testing.B) {
		attr := NewAttribute(1, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = attr.GetValue()
		}
	})

	b.Run("tagged", func(b *testing.B) {
		attr := NewTaggedAttribute(64, 5, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = attr.GetValue()
		}
	})
}

func BenchmarkVendorAttributeGetValue(b *testing.B) {
	b.Run("regular", func(b *testing.B) {
		va := NewVendorAttribute(4874, 13, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = va.GetValue()
		}
	})

	b.Run("tagged", func(b *testing.B) {
		va := NewTaggedVendorAttribute(4874, 1, 3, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = va.GetValue()
		}
	})
}

func BenchmarkAttributeString(b *testing.B) {
	b.Run("regular", func(b *testing.B) {
		attr := NewAttribute(1, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = attr.String()
		}
	})

	b.Run("tagged", func(b *testing.B) {
		attr := NewTaggedAttribute(64, 5, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = attr.String()
		}
	})
}

func BenchmarkVendorAttributeString(b *testing.B) {
	b.Run("regular", func(b *testing.B) {
		va := NewVendorAttribute(4874, 13, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = va.String()
		}
	})

	b.Run("tagged", func(b *testing.B) {
		va := NewTaggedVendorAttribute(4874, 1, 3, []byte("testvalue"))
		b.ResetTimer()
		b.ReportAllocs()
		for b.Loop() {
			_ = va.String()
		}
	})
}

func BenchmarkVendorAttributeToVSA(b *testing.B) {
	va := NewVendorAttribute(4874, 13, []byte("8.8.8.8"))
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_ = va.ToVSA()
	}
}

func BenchmarkParseVSA(b *testing.B) {
	va := NewVendorAttribute(4874, 13, []byte("testvalue"))
	attr := va.ToVSA()
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = ParseVSA(attr)
	}
}

func BenchmarkVSARoundTrip(b *testing.B) {
	value := []byte("testvalue")
	b.ReportAllocs()
	for b.Loop() {
		va := NewVendorAttribute(4874, 13, value)
		attr := va.ToVSA()
		_, _ = ParseVSA(attr)
	}
}
