package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEricssonVendorDefinition(t *testing.T) {
	assert.NotNil(t, EricssonVendorDefinition)
	assert.Equal(t, uint32(193), EricssonVendorDefinition.ID)
	assert.Equal(t, "ericsson", EricssonVendorDefinition.Name)
	assert.Len(t, EricssonVendorDefinition.Attributes, 110)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range EricssonVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("sitekeeper and call routing attributes", func(t *testing.T) {
		sk, ok := attrMap["ericsson-sitekeeper-name"]
		require.True(t, ok)
		assert.Equal(t, uint32(58), sk.ID)
		assert.Equal(t, DataTypeString, sk.DataType)

		proxy, ok := attrMap["ericsson-proxy-ip-address"]
		require.True(t, ok)
		assert.Equal(t, DataTypeIPAddr, proxy.DataType)
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range EricssonVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}

func TestEricssonPCNVendorDefinition(t *testing.T) {
	assert.NotNil(t, EricssonPCNVendorDefinition)
	assert.Equal(t, uint32(10923), EricssonPCNVendorDefinition.ID)
	assert.Equal(t, "ericsson-pcn", EricssonPCNVendorDefinition.Name)
	assert.Len(t, EricssonPCNVendorDefinition.Attributes, 2)

	rule := EricssonPCNVendorDefinition.Attributes[0]
	assert.Equal(t, uint32(30), rule.ID)
	assert.Equal(t, "ericsson-pcn-suggested-rule-space", rule.Name)
	assert.Equal(t, DataTypeString, rule.DataType)
}
