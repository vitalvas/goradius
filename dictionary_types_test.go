package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtendedBaseType(t *testing.T) {
	tests := []struct {
		name         string
		id           uint32
		expectedBase uint8
		expectedExt  uint8
	}{
		{"base 241 ext 1", 241*256 + 1, 241, 1},
		{"base 245 ext 5", 245*256 + 5, 245, 5},
		{"base 246 ext 255", 246*256 + 255, 246, 255},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attr := &AttributeDefinition{ID: tc.id}
			assert.Equal(t, tc.expectedBase, attr.ExtendedBaseType())
			assert.Equal(t, tc.expectedExt, attr.ExtendedType())
		})
	}
}

func TestIsExtendedBaseType(t *testing.T) {
	for _, v := range []uint8{241, 242, 243, 244, 245, 246} {
		assert.True(t, IsExtendedBaseType(v), "type %d should be extended", v)
	}
	for _, v := range []uint8{0, 1, 26, 240, 247, 255} {
		assert.False(t, IsExtendedBaseType(v), "type %d should not be extended", v)
	}
}

func TestIsLongExtendedBaseType(t *testing.T) {
	for _, v := range []uint8{245, 246} {
		assert.True(t, IsLongExtendedBaseType(v), "type %d should be long extended", v)
	}
	for _, v := range []uint8{241, 242, 243, 244, 247} {
		assert.False(t, IsLongExtendedBaseType(v), "type %d should not be long extended", v)
	}
}

func dictTypesChildParent() *AttributeDefinition {
	return &AttributeDefinition{
		ID:       1,
		Name:     "parent-tlv",
		DataType: DataTypeTLV,
		Children: []*AttributeDefinition{
			{ID: 1, Name: "child-a", DataType: DataTypeString},
			{ID: 2, Name: "child-b", DataType: DataTypeInteger},
			{ID: 3, Name: "child-c", DataType: DataTypeIPAddr},
		},
	}
}

func BenchmarkLookupChildByID(b *testing.B) {
	parent := dictTypesChildParent()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = parent.LookupChildByID(3)
	}
}

func BenchmarkLookupChildByName(b *testing.B) {
	parent := dictTypesChildParent()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = parent.LookupChildByName("child-c")
	}
}

func BenchmarkExtendedBaseType(b *testing.B) {
	attr := &AttributeDefinition{ID: 245*ExtendedIDShift + 5}
	b.ReportAllocs()
	for b.Loop() {
		_ = attr.ExtendedBaseType()
		_ = attr.ExtendedType()
	}
}

func BenchmarkIsExtendedBaseType(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = IsExtendedBaseType(245)
		_ = IsLongExtendedBaseType(245)
	}
}

// FuzzExtendedTypePacking ensures the base-type/extended-type packing used for extended
// attribute IDs round-trips for every base type and extended type.
func FuzzExtendedTypePacking(f *testing.F) {
	f.Add(uint8(241), uint8(1))
	f.Add(uint8(246), uint8(255))
	f.Add(uint8(0), uint8(0))

	f.Fuzz(func(t *testing.T, base, ext uint8) {
		attr := &AttributeDefinition{ID: uint32(base)*ExtendedIDShift + uint32(ext)}
		assert.Equal(t, base, attr.ExtendedBaseType(), "base type must survive packing")
		assert.Equal(t, ext, attr.ExtendedType(), "extended type must survive packing")

		// IsExtendedBaseType / IsLongExtendedBaseType must be internally consistent:
		// every long extended type is also an extended type.
		if IsLongExtendedBaseType(base) {
			assert.True(t, IsExtendedBaseType(base), "long extended type %d must be extended", base)
		}
	})
}
