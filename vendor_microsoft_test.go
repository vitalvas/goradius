package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMicrosoftVendorDefinition(t *testing.T) {
	assert.NotNil(t, MicrosoftVendorDefinition)
	assert.Equal(t, uint32(311), MicrosoftVendorDefinition.ID)
	assert.Equal(t, "microsoft", MicrosoftVendorDefinition.Name)
	assert.Len(t, MicrosoftVendorDefinition.Attributes, 58)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range MicrosoftVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("dns servers", func(t *testing.T) {
		primary, ok := attrMap["ms-primary-dns-server"]
		require.True(t, ok)
		assert.Equal(t, uint32(28), primary.ID)
		assert.Equal(t, DataTypeIPAddr, primary.DataType)

		secondary, ok := attrMap["ms-secondary-dns-server"]
		require.True(t, ok)
		assert.Equal(t, uint32(29), secondary.ID)
	})

	t.Run("mppe keys are salt encrypted", func(t *testing.T) {
		send, ok := attrMap["ms-mppe-send-key"]
		require.True(t, ok)
		assert.Equal(t, uint32(16), send.ID)
		assert.Equal(t, EncryptionTunnelPassword, send.Encryption)

		recv, ok := attrMap["ms-mppe-recv-key"]
		require.True(t, ok)
		assert.Equal(t, uint32(17), recv.ID)
		assert.Equal(t, EncryptionTunnelPassword, recv.Encryption)
	})

	t.Run("chap mppe keys use request authenticator cipher", func(t *testing.T) {
		keys, ok := attrMap["ms-chap-mppe-keys"]
		require.True(t, ok)
		assert.Equal(t, uint32(12), keys.ID)
		assert.Equal(t, EncryptionUserPassword, keys.Encryption)
	})

	t.Run("chap2 response", func(t *testing.T) {
		resp, ok := attrMap["ms-chap2-response"]
		require.True(t, ok)
		assert.Equal(t, uint32(25), resp.ID)
		assert.Equal(t, DataTypeOctets, resp.DataType)
	})
}

func TestNoDuplicateMicrosoftAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)
	for _, attr := range MicrosoftVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Microsoft attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestMicrosoftRegisteredInDefault(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	vendor, ok := dict.LookupVendorByID(311)
	require.True(t, ok)
	assert.Equal(t, "microsoft", vendor.Name)

	attr, ok := dict.LookupByAttributeName("ms-primary-dns-server")
	require.True(t, ok)
	assert.Equal(t, uint32(28), attr.ID)
}
