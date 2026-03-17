package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestJuniperVendorDefinition(t *testing.T) {
	assert.NotNil(t, JuniperVendorDefinition)
	assert.Equal(t, uint32(2636), JuniperVendorDefinition.ID)
	assert.Equal(t, "juniper", JuniperVendorDefinition.Name)
	assert.NotEmpty(t, JuniperVendorDefinition.Attributes)

	// Check Juniper attributes
	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range JuniperVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify Juniper-User-Permissions exists and has multiline enabled
	userPerms, exists := attrMap["juniper-user-permissions"]
	assert.True(t, exists, "juniper-user-permissions should exist")
	if exists {
		assert.Equal(t, uint32(10), userPerms.ID)
		assert.Equal(t, DataTypeString, userPerms.DataType)
		assert.True(t, userPerms.Multiline, "juniper-user-permissions should support multiline")
	}

	// Verify Juniper-Allow-Commands has multiline enabled
	allowCmds, exists := attrMap["juniper-allow-commands"]
	assert.True(t, exists, "juniper-allow-commands should exist")
	if exists {
		assert.Equal(t, uint32(2), allowCmds.ID)
		assert.True(t, allowCmds.Multiline, "juniper-allow-commands should support multiline")
	}

	// Verify Juniper-CTP-Group has enumerated values
	ctpGroup, exists := attrMap["juniper-ctp-group"]
	assert.True(t, exists, "juniper-ctp-group should exist")
	if exists {
		assert.Equal(t, uint32(21), ctpGroup.ID)
		assert.Equal(t, DataTypeInteger, ctpGroup.DataType)
		assert.NotNil(t, ctpGroup.Values)
		assert.Equal(t, uint32(1), ctpGroup.Values["read_only"])
		assert.Equal(t, uint32(2), ctpGroup.Values["admin"])
		assert.Equal(t, uint32(3), ctpGroup.Values["privileged_admin"])
		assert.Equal(t, uint32(4), ctpGroup.Values["auditor"])
	}

	// Verify Juniper-Primary-Dns exists
	primaryDNS, exists := attrMap["juniper-primary-dns"]
	assert.True(t, exists, "juniper-primary-dns should exist")
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
