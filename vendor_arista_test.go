package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAristaVendorDefinition(t *testing.T) {
	assert.NotNil(t, AristaVendorDefinition)
	assert.Equal(t, uint32(30065), AristaVendorDefinition.ID)
	assert.Equal(t, "arista", AristaVendorDefinition.Name)
	assert.Len(t, AristaVendorDefinition.Attributes, 10)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range AristaVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("avpair is the generic container", func(t *testing.T) {
		avPair, ok := attrMap["arista-avpair"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), avPair.ID)
		assert.Equal(t, DataTypeString, avPair.DataType)
		assert.Equal(t, AttributeUsage(0), avPair.Usage)
	})

	t.Run("webauth values", func(t *testing.T) {
		webAuth, ok := attrMap["arista-webauth"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, webAuth.DataType)
		assert.Equal(t, uint32(1), webAuth.Values["start"])
		assert.Equal(t, uint32(2), webAuth.Values["complete"])
	})

	t.Run("all attributes stay unrestricted", func(t *testing.T) {
		for _, attr := range AristaVendorDefinition.Attributes {
			assert.Equal(t, AttributeUsage(0), attr.Usage, attr.Name)
		}
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range AristaVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
