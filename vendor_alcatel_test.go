package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAlcatelVendorDefinition(t *testing.T) {
	assert.NotNil(t, AlcatelVendorDefinition)
	assert.Equal(t, uint32(3041), AlcatelVendorDefinition.ID)
	assert.Equal(t, "alcatel", AlcatelVendorDefinition.Name)
	assert.Len(t, AlcatelVendorDefinition.Attributes, 41)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range AlcatelVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("auth type values", func(t *testing.T) {
		auth, ok := attrMap["aat-auth-type"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, auth.DataType)
		assert.Equal(t, uint32(0), auth.Values["aat-auth-none"])
		assert.Equal(t, uint32(3), auth.Values["aat-auth-pap"])
		assert.Equal(t, uint32(5), auth.Values["aat-auth-ms-chap"])
	})

	t.Run("ip tos bitmask values", func(t *testing.T) {
		tos, ok := attrMap["aat-ip-tos"]
		require.True(t, ok)
		assert.Equal(t, uint32(16), tos.Values["ip-tos-latency"])

		applyTo, ok := attrMap["aat-ip-tos-apply-to"]
		require.True(t, ok)
		assert.Equal(t, uint32(3072), applyTo.Values["ip-tos-apply-to-both"])
	})

	t.Run("client dns is ipaddr", func(t *testing.T) {
		dns, ok := attrMap["aat-client-primary-dns"]
		require.True(t, ok)
		assert.Equal(t, uint32(5), dns.ID)
		assert.Equal(t, DataTypeIPAddr, dns.DataType)
	})

	t.Run("all attributes stay unrestricted", func(t *testing.T) {
		for _, attr := range AlcatelVendorDefinition.Attributes {
			assert.Equal(t, AttributeUsage(0), attr.Usage, attr.Name)
		}
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range AlcatelVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
