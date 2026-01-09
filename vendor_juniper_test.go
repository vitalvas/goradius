package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJuniperVendorDefinition(t *testing.T) {
	assert.NotNil(t, JuniperVendorDefinition)
	assert.Equal(t, uint32(2636), JuniperVendorDefinition.ID)
	assert.Equal(t, "Juniper", JuniperVendorDefinition.Name)
	assert.NotEmpty(t, JuniperVendorDefinition.Attributes)

	// Check Juniper attributes
	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range JuniperVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify Juniper-User-Permissions exists and has multiline enabled
	userPerms, exists := attrMap["Juniper-User-Permissions"]
	assert.True(t, exists, "Juniper-User-Permissions should exist")
	if exists {
		assert.Equal(t, uint32(10), userPerms.ID)
		assert.Equal(t, DataTypeString, userPerms.DataType)
		assert.True(t, userPerms.Multiline, "Juniper-User-Permissions should support multiline")
	}

	// Verify Juniper-Allow-Commands has multiline enabled
	allowCmds, exists := attrMap["Juniper-Allow-Commands"]
	assert.True(t, exists, "Juniper-Allow-Commands should exist")
	if exists {
		assert.Equal(t, uint32(2), allowCmds.ID)
		assert.True(t, allowCmds.Multiline, "Juniper-Allow-Commands should support multiline")
	}

	// Verify Juniper-CTP-Group has enumerated values
	ctpGroup, exists := attrMap["Juniper-CTP-Group"]
	assert.True(t, exists, "Juniper-CTP-Group should exist")
	if exists {
		assert.Equal(t, uint32(21), ctpGroup.ID)
		assert.Equal(t, DataTypeInteger, ctpGroup.DataType)
		assert.NotNil(t, ctpGroup.Values)
		assert.Equal(t, uint32(1), ctpGroup.Values["Read_Only"])
		assert.Equal(t, uint32(2), ctpGroup.Values["Admin"])
		assert.Equal(t, uint32(3), ctpGroup.Values["Privileged_Admin"])
		assert.Equal(t, uint32(4), ctpGroup.Values["Auditor"])
	}

	// Verify Juniper-Primary-Dns exists
	primaryDNS, exists := attrMap["Juniper-Primary-Dns"]
	assert.True(t, exists, "Juniper-Primary-Dns should exist")
	if exists {
		assert.Equal(t, uint32(31), primaryDNS.ID)
		assert.Equal(t, DataTypeIPAddr, primaryDNS.DataType)
	}
}

func TestNoDuplicateJuniperAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range JuniperVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Juniper attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}
