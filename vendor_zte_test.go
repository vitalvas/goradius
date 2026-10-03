package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZTEVendorDefinition(t *testing.T) {
	assert.NotNil(t, ZTEVendorDefinition)
	assert.Equal(t, uint32(3902), ZTEVendorDefinition.ID)
	assert.Equal(t, "zte", ZTEVendorDefinition.Name)
	assert.Len(t, ZTEVendorDefinition.Attributes, 49)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range ZTEVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("dns servers carried as text", func(t *testing.T) {
		pri, ok := attrMap["zte-client-dns-pri"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), pri.ID)
		assert.Equal(t, DataTypeString, pri.DataType)

		sec, ok := attrMap["zte-client-dns-sec"]
		require.True(t, ok)
		assert.Equal(t, DataTypeString, sec.DataType)
	})

	t.Run("qos rate control family", func(t *testing.T) {
		down, ok := attrMap["zte-qos-profile-down"]
		require.True(t, ok)
		assert.Equal(t, uint32(82), down.ID)
		assert.Equal(t, DataTypeString, down.DataType)

		scrUp, ok := attrMap["zte-rate-ctrl-scr-up"]
		require.True(t, ok)
		assert.Equal(t, uint32(89), scrUp.ID)
		assert.Equal(t, DataTypeInteger, scrUp.DataType)

		v6, ok := attrMap["zte-qos-profile-down-v6"]
		require.True(t, ok)
		assert.Equal(t, uint32(237), v6.ID)
	})

	t.Run("all attributes stay unrestricted", func(t *testing.T) {
		for _, attr := range ZTEVendorDefinition.Attributes {
			assert.Equal(t, AttributeUsage(0), attr.Usage, attr.Name)
		}
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range ZTEVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
