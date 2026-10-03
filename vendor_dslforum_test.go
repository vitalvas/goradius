package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDSLForumVendorDefinition(t *testing.T) {
	assert.NotNil(t, DSLForumVendorDefinition)
	assert.Equal(t, uint32(3561), DSLForumVendorDefinition.ID)
	assert.Equal(t, "dslforum", DSLForumVendorDefinition.Name)
	assert.Len(t, DSLForumVendorDefinition.Attributes, 36)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range DSLForumVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("agent circuit and remote id", func(t *testing.T) {
		circuit, ok := attrMap["adsl-agent-circuit-id"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), circuit.ID)
		assert.Equal(t, DataTypeString, circuit.DataType)

		remote, ok := attrMap["adsl-agent-remote-id"]
		require.True(t, ok)
		assert.Equal(t, uint32(2), remote.ID)
	})

	t.Run("access line rates", func(t *testing.T) {
		up, ok := attrMap["adsl-actual-data-rate-upstream"]
		require.True(t, ok)
		assert.Equal(t, uint32(129), up.ID)
		assert.Equal(t, DataTypeInteger, up.DataType)
	})

	t.Run("dsl type enum", func(t *testing.T) {
		dslType, ok := attrMap["adsl-dsl-type"]
		require.True(t, ok)
		assert.Equal(t, uint32(145), dslType.ID)
		assert.Equal(t, uint32(3), dslType.Values["adsl2-plus"])
		assert.Equal(t, uint32(8), dslType.Values["g.fast"])
	})

	t.Run("pon access type enum", func(t *testing.T) {
		ponType, ok := attrMap["adsl-pon-access-type"]
		require.True(t, ok)
		assert.Equal(t, uint32(146), ponType.ID)
		assert.Equal(t, uint32(1), ponType.Values["gpon"])
		assert.Equal(t, uint32(4), ponType.Values["xgs-pon"])
	})
}

func TestNoDuplicateDSLForumAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)
	for _, attr := range DSLForumVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate DSL Forum attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestDSLForumRegisteredInDefault(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	vendor, ok := dict.LookupVendorByID(3561)
	require.True(t, ok)
	assert.Equal(t, "dslforum", vendor.Name)

	attr, ok := dict.LookupByAttributeName("adsl-agent-circuit-id")
	require.True(t, ok)
	assert.Equal(t, uint32(1), attr.ID)
}
