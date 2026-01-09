package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestERXVendorDefinition(t *testing.T) {
	assert.NotNil(t, ERXVendorDefinition)
	assert.Equal(t, uint32(4874), ERXVendorDefinition.ID)
	assert.Equal(t, "ERX", ERXVendorDefinition.Name)
	assert.NotEmpty(t, ERXVendorDefinition.Attributes)

	// Check some known ERX attributes
	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range ERXVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify ERX-Service-Activate exists and has tag
	serviceActivate, exists := attrMap["ERX-Service-Activate"]
	assert.True(t, exists, "ERX-Service-Activate should exist")
	if exists {
		assert.True(t, serviceActivate.HasTag, "ERX-Service-Activate should support tags")
		assert.Equal(t, DataTypeString, serviceActivate.DataType)
	}

	// Verify ERX-Primary-Dns exists
	primaryDNS, exists := attrMap["ERX-Primary-Dns"]
	assert.True(t, exists, "ERX-Primary-Dns should exist")
	if exists {
		assert.Equal(t, DataTypeIPAddr, primaryDNS.DataType)
	}
}

func TestNoDuplicateERXAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range ERXVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate ERX attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}
