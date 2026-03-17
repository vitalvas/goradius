package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMikrotikVendorDefinition(t *testing.T) {
	assert.NotNil(t, MikrotikVendorDefinition)
	assert.Equal(t, uint32(14988), MikrotikVendorDefinition.ID)
	assert.Equal(t, "mikrotik", MikrotikVendorDefinition.Name)
	assert.NotEmpty(t, MikrotikVendorDefinition.Attributes)

	// Check known Mikrotik attributes
	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range MikrotikVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify Mikrotik-Recv-Limit exists
	recvLimit, exists := attrMap["mikrotik-recv-limit"]
	assert.True(t, exists, "mikrotik-recv-limit should exist")
	if exists {
		assert.Equal(t, uint32(1), recvLimit.ID)
		assert.Equal(t, DataTypeInteger, recvLimit.DataType)
	}

	// Verify Mikrotik-Group exists
	group, exists := attrMap["mikrotik-group"]
	assert.True(t, exists, "mikrotik-group should exist")
	if exists {
		assert.Equal(t, uint32(3), group.ID)
		assert.Equal(t, DataTypeString, group.DataType)
	}

	// Verify Mikrotik-Host-IP exists
	hostIP, exists := attrMap["mikrotik-host-ip"]
	assert.True(t, exists, "mikrotik-host-ip should exist")
	if exists {
		assert.Equal(t, uint32(10), hostIP.ID)
		assert.Equal(t, DataTypeIPAddr, hostIP.DataType)
	}

	// Verify Mikrotik-Wireless-Enc-Algo exists and has values
	encAlgo, exists := attrMap["mikrotik-wireless-enc-algo"]
	assert.True(t, exists, "mikrotik-wireless-enc-algo should exist")
	if exists {
		assert.Equal(t, uint32(6), encAlgo.ID)
		assert.Equal(t, DataTypeInteger, encAlgo.DataType)

		// Verify values for Mikrotik-Wireless-Enc-Algo
		assert.NotNil(t, encAlgo.Values, "mikrotik-wireless-enc-algo should have defined values")
		if encAlgo.Values != nil {
			assert.Equal(t, uint32(0), encAlgo.Values["no-encryption"])
			assert.Equal(t, uint32(1), encAlgo.Values["40-bit-wep"])
			assert.Equal(t, uint32(2), encAlgo.Values["104-bit-wep"])
			assert.Equal(t, uint32(3), encAlgo.Values["aes-ccm"])
			assert.Equal(t, uint32(4), encAlgo.Values["tkip"])
		}
	}

	// Verify all 29 attributes exist
	assert.Len(t, MikrotikVendorDefinition.Attributes, 29)
}

func TestNoDuplicateMikrotikAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range MikrotikVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Mikrotik attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}
