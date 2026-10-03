package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestA10VendorDefinition(t *testing.T) {
	assert.NotNil(t, A10VendorDefinition)
	assert.Equal(t, uint32(22610), A10VendorDefinition.ID)
	assert.Equal(t, "a10", A10VendorDefinition.Name)
	assert.Len(t, A10VendorDefinition.Attributes, 5)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range A10VendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("admin privilege values", func(t *testing.T) {
		priv, ok := attrMap["a10-admin-privilege"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, priv.DataType)
		assert.Equal(t, uint32(1), priv.Values["read-only-admin"])
		assert.Equal(t, uint32(2), priv.Values["read-write-admin"])
		assert.Equal(t, uint32(8), priv.Values["partition-read-write"])
	})

	t.Run("admin attributes only in access-accept", func(t *testing.T) {
		for _, name := range []string{
			"a10-admin-privilege", "a10-admin-partition",
			"a10-admin-access-type", "a10-admin-role",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.True(t, attr.AllowedIn(CodeAccessAccept), name)
			assert.False(t, attr.AllowedIn(CodeAccessRequest), name)
		}
	})

	t.Run("app name stays unrestricted", func(t *testing.T) {
		appName, ok := attrMap["a10-app-name"]
		require.True(t, ok)
		assert.Equal(t, AttributeUsage(0), appName.Usage)
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range A10VendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
