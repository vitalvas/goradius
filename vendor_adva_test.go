package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdvaVendorDefinition(t *testing.T) {
	assert.NotNil(t, AdvaVendorDefinition)
	assert.Equal(t, uint32(2544), AdvaVendorDefinition.ID)
	assert.Equal(t, "adva", AdvaVendorDefinition.Name)
	assert.Len(t, AdvaVendorDefinition.Attributes, 3)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range AdvaVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("user level values", func(t *testing.T) {
		level, ok := attrMap["adva-user-level"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, level.DataType)
		assert.Equal(t, uint32(0), level.Values["retrieve"])
		assert.Equal(t, uint32(5), level.Values["super"])
	})

	t.Run("uum user level has monitor zero and sudoadmin eight", func(t *testing.T) {
		uum, ok := attrMap["adva-uum-user-level"]
		require.True(t, ok)
		assert.Equal(t, uint32(102), uum.ID)
		assert.Equal(t, uint32(0), uum.Values["monitor"])
		assert.Equal(t, uint32(8), uum.Values["sudoadmin"])
	})

	t.Run("network manager auth level is string", func(t *testing.T) {
		nm, ok := attrMap["adva-auth-level-nm"]
		require.True(t, ok)
		assert.Equal(t, uint32(101), nm.ID)
		assert.Equal(t, DataTypeString, nm.DataType)
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range AdvaVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
