package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAristaWiFiVendorDefinition(t *testing.T) {
	assert.NotNil(t, AristaWiFiVendorDefinition)
	assert.Equal(t, uint32(16901), AristaWiFiVendorDefinition.ID)
	assert.Equal(t, "arista-wifi", AristaWiFiVendorDefinition.Name)
	assert.Len(t, AristaWiFiVendorDefinition.Attributes, 18)

	attrMap := make(map[uint32]*AttributeDefinition)
	for _, attr := range AristaWiFiVendorDefinition.Attributes {
		attrMap[attr.ID] = attr
	}

	t.Run("bandwidth limits are integers", func(t *testing.T) {
		download, ok := attrMap[5]
		require.True(t, ok)
		assert.Equal(t, "arista-wifi-download-limit", download.Name)
		assert.Equal(t, DataTypeInteger, download.DataType)

		upload, ok := attrMap[6]
		require.True(t, ok)
		assert.Equal(t, "arista-wifi-upload-limit", upload.Name)
		assert.Equal(t, DataTypeInteger, upload.DataType)
	})

	t.Run("reserved ids are omitted", func(t *testing.T) {
		_, nine := attrMap[9]
		_, ten := attrMap[10]
		assert.False(t, nine, "ID 9 is reserved in the official dictionary")
		assert.False(t, ten, "ID 10 is reserved in the official dictionary")
	})

	t.Run("no name clash with the eos vendor", func(t *testing.T) {
		dict, err := NewDefault()
		require.NoError(t, err)

		eos, ok := dict.LookupByAttributeName("arista-captive-portal")
		require.True(t, ok)
		assert.Equal(t, uint32(10), eos.ID)

		wifi, ok := dict.LookupByAttributeName("arista-wifi-captive-portal")
		require.True(t, ok)
		assert.Equal(t, uint32(8), wifi.ID)
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range AristaWiFiVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
