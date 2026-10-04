package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEricssonABVendorDefinition(t *testing.T) {
	assert.NotNil(t, EricssonABVendorDefinition)
	assert.Equal(t, uint32(2352), EricssonABVendorDefinition.ID)
	assert.Equal(t, "ericsson-ab", EricssonABVendorDefinition.Name)
	assert.Len(t, EricssonABVendorDefinition.Attributes, 211)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range EricssonABVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("service attributes carry tags", func(t *testing.T) {
		for _, name := range []string{
			"ericsson-ab-tunnel-hello-timer", "ericsson-ab-service-name",
			"ericsson-ab-service-action", "ericsson-ab-service-parameter",
			"ericsson-ab-service-error-cause", "ericsson-ab-deactivate-service-name",
			"ericsson-ab-reauth-service-name",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.True(t, attr.HasTag, name)
		}
	})

	t.Run("service action zero is de-activate", func(t *testing.T) {
		action, ok := attrMap["ericsson-ab-service-action"]
		require.True(t, ok)
		assert.Equal(t, uint32(0), action.Values["de-activate"])
		assert.Equal(t, uint32(2), action.Values["activate-without-acct"])
	})

	t.Run("platform types", func(t *testing.T) {
		plat, ok := attrMap["ericsson-ab-platform-type"]
		require.True(t, ok)
		assert.Equal(t, uint32(2), plat.Values["smartedge-800"])
	})

	t.Run("64-bit counters use integer64", func(t *testing.T) {
		for _, name := range []string{
			"ericsson-ab-acct-input-octets-64", "ericsson-ab-acct-output-packets-64",
			"ericsson-ab-acct-mcast-in-octets-64",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.Equal(t, DataTypeInteger64, attr.DataType, name)
		}
	})

	t.Run("dsl transmission system values", func(t *testing.T) {
		dsl, ok := attrMap["ericsson-ab-dsl-transmission-system"]
		require.True(t, ok)
		assert.Equal(t, uint32(3), dsl.Values["adsl2+"])
		assert.Equal(t, uint32(7), dsl.Values["unknown"])
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range EricssonABVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
