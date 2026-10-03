package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestF5VendorDefinition(t *testing.T) {
	assert.NotNil(t, F5VendorDefinition)
	assert.Equal(t, uint32(3375), F5VendorDefinition.ID)
	assert.Equal(t, "f5", F5VendorDefinition.Name)
	assert.Len(t, F5VendorDefinition.Attributes, 10)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range F5VendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("user role values", func(t *testing.T) {
		role, ok := attrMap["f5-ltm-user-role"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, role.DataType)
		assert.Equal(t, uint32(0), role.Values["administrator"])
		assert.Equal(t, uint32(100), role.Values["manager"])
		assert.Equal(t, uint32(400), role.Values["operator"])
		assert.Equal(t, uint32(700), role.Values["guest"])
		assert.Equal(t, uint32(900), role.Values["no-access"])
	})

	t.Run("remote role attributes only in access-accept", func(t *testing.T) {
		for _, name := range []string{
			"f5-ltm-user-role", "f5-ltm-user-role-universal",
			"f5-ltm-user-partition", "f5-ltm-user-console",
			"f5-ltm-user-shell", "f5-ltm-user-context-1",
			"f5-ltm-user-context-2", "f5-ltm-user-info-1",
			"f5-ltm-user-info-2",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.True(t, attr.AllowedIn(CodeAccessAccept), name)
			assert.False(t, attr.AllowedIn(CodeAccessRequest), name)
		}
	})

	t.Run("audit message only in accounting-request", func(t *testing.T) {
		audit, ok := attrMap["f5-ltm-audit-msg"]
		require.True(t, ok)
		assert.Equal(t, DataTypeString, audit.DataType)
		assert.True(t, audit.AllowedIn(CodeAccountingRequest))
		assert.False(t, audit.AllowedIn(CodeAccessAccept))
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range F5VendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
