package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNokiaSRVendorDefinition(t *testing.T) {
	assert.NotNil(t, NokiaSRVendorDefinition)
	assert.Equal(t, uint32(6527), NokiaSRVendorDefinition.ID)
	assert.Equal(t, "nokia-sr", NokiaSRVendorDefinition.Name)
	assert.Len(t, NokiaSRVendorDefinition.Attributes, 190)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range NokiaSRVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("timetra access values", func(t *testing.T) {
		access, ok := attrMap["nokia-sr-timetra-access"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), access.Values["ftp"])
		assert.Equal(t, uint32(3), access.Values["both"])
	})

	t.Run("tunnel attributes carry tags", func(t *testing.T) {
		for _, name := range []string{
			"nokia-sr-tunnel-max-sessions", "nokia-sr-tunnel-idle-timeout",
			"nokia-sr-tunnel-avp-hiding", "nokia-sr-tunnel-challenge",
			"nokia-sr-tunnel-acct-policy", "nokia-sr-acct-interim-level",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.True(t, attr.HasTag, name)
		}
	})

	t.Run("lawful intercept uses tunnel-password encryption", func(t *testing.T) {
		for _, name := range []string{
			"nokia-sr-li-action", "nokia-sr-li-destination", "nokia-sr-li-fc",
			"nokia-sr-li-direction", "nokia-sr-li-intercept-id",
			"nokia-sr-li-session-id", "nokia-sr-apn-password",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.Equal(t, EncryptionTunnelPassword, attr.Encryption, name)
		}
	})

	t.Run("li-fc best-effort value is zero", func(t *testing.T) {
		fc, ok := attrMap["nokia-sr-li-fc"]
		require.True(t, ok)
		assert.Equal(t, uint32(0), fc.Values["be"])
		assert.Equal(t, uint32(7), fc.Values["nc"])
	})

	t.Run("accounting counters carried as octets", func(t *testing.T) {
		counter, ok := attrMap["nokia-sr-acct-i-inprof-octets-64"]
		require.True(t, ok)
		assert.Equal(t, DataTypeOctets, counter.DataType)
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range NokiaSRVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
