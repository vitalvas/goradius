package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCienaVendorDefinition(t *testing.T) {
	assert.NotNil(t, CienaVendorDefinition)
	assert.Equal(t, uint32(1271), CienaVendorDefinition.ID)
	assert.Equal(t, "ciena", CienaVendorDefinition.Name)
	assert.Len(t, CienaVendorDefinition.Attributes, 19)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range CienaVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("privilege level values", func(t *testing.T) {
		ces, ok := attrMap["ciena-ces-priv-level"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, ces.DataType)
		assert.Equal(t, uint32(1), ces.Values["limited"])
		assert.Equal(t, uint32(3), ces.Values["super-user"])

		cs, ok := attrMap["ciena-cs-priv-level"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), cs.Values["read-only"])
		assert.Equal(t, uint32(9), cs.Values["ne-admin"])
	})

	t.Run("blue planet role in access-accept only", func(t *testing.T) {
		role, ok := attrMap["ciena-bp-role"]
		require.True(t, ok)
		assert.Equal(t, uint32(220), role.ID)
		assert.True(t, role.AllowedIn(CodeAccessAccept))
		assert.False(t, role.AllowedIn(CodeAccessRequest))
	})

	t.Run("client ip is ipaddr", func(t *testing.T) {
		clientIP, ok := attrMap["ciena-cs-client-ip"]
		require.True(t, ok)
		assert.Equal(t, DataTypeIPAddr, clientIP.DataType)
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range CienaVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
