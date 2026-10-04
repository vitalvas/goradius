package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBenuVendorDefinition(t *testing.T) {
	assert.NotNil(t, BenuVendorDefinition)
	assert.Equal(t, uint32(39406), BenuVendorDefinition.ID)
	assert.Equal(t, "benu", BenuVendorDefinition.Name)
	assert.Len(t, BenuVendorDefinition.Attributes, 152)

	attrMap := make(map[string]*AttributeDefinition)
	idMap := make(map[uint32]*AttributeDefinition)
	for _, attr := range BenuVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
		idMap[attr.ID] = attr
	}

	t.Run("registration type values", func(t *testing.T) {
		reg, ok := attrMap["benu-registration-type"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), reg.Values["dhcpv4"])
		assert.Equal(t, uint32(7), reg.Values["pppoe"])
		assert.Equal(t, uint32(8), reg.Values["ppp"])
	})

	t.Run("changelog usage masks", func(t *testing.T) {
		wifi, ok := attrMap["benu-wifi-service"]
		require.True(t, ok)
		assert.True(t, wifi.AllowedIn(CodeAccessAccept))
		assert.True(t, wifi.AllowedIn(CodeAccountingRequest))
		assert.False(t, wifi.AllowedIn(CodeAccessRequest))

		deviceType, ok := attrMap["benu-device-type"]
		require.True(t, ok)
		assert.True(t, deviceType.AllowedIn(CodeAccessRequest))
		assert.False(t, deviceType.AllowedIn(CodeAccessAccept))

		volume, ok := attrMap["benu-upstream-volume-limit"]
		require.True(t, ok)
		assert.True(t, volume.AllowedIn(CodeAccessAccept))
		assert.True(t, volume.AllowedIn(CodeCoARequest))
		assert.False(t, volume.AllowedIn(CodeAccountingRequest))

		reply, ok := attrMap["benu-reply-message"]
		require.True(t, ok)
		assert.True(t, reply.AllowedIn(CodeCoANAK))
		assert.False(t, reply.AllowedIn(CodeCoARequest))

		dmAction, ok := attrMap["benu-dm-action"]
		require.True(t, ok)
		assert.True(t, dmAction.AllowedIn(CodeDisconnectRequest))
		assert.False(t, dmAction.AllowedIn(CodeCoARequest))
	})

	t.Run("encrypted attributes use user-password cipher", func(t *testing.T) {
		for _, name := range []string{
			"benu-enc-li-policy", "benu-enc-li-id", "benu-enc-li-server-port",
			"benu-enc-li-server-address", "benu-enc-li-action",
			"benu-enc-calling-station-id", "benu-enc-li-server-ipv6-address",
			"benu-enc-li-server6-port", "benu-enc-li-source-port",
			"benu-enc-li-source-address", "benu-enc-li-source-ipv6-address",
			"benu-enc-li-source6-port", "benu-enc-li-header-field",
			"benu-enc-li-ipsec-policy",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.Equal(t, EncryptionUserPassword, attr.Encryption, name)
		}
	})

	t.Run("undefined ids are omitted", func(t *testing.T) {
		for _, id := range []uint32{1, 5, 6, 7, 8, 11} {
			_, exists := idMap[id]
			assert.False(t, exists, "ID %d must not be defined", id)
		}
	})

	t.Run("byte attributes use byte type with enums", func(t *testing.T) {
		for _, name := range []string{
			"benu-igmp-fast-leave", "benu-igmp-router-alert", "benu-mcast-replica-type",
		} {
			attr, ok := attrMap[name]
			require.True(t, ok, name)
			assert.Equal(t, DataTypeByte, attr.DataType, name)
		}
		assert.Equal(t, uint32(0), attrMap["benu-mcast-replica-type"].Values["non-mvlan"])
		assert.Equal(t, uint32(2), attrMap["benu-igmp-fast-leave"].Values["disable"])
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range BenuVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
