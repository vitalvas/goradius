package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWISPrVendorDefinition(t *testing.T) {
	assert.NotNil(t, WISPrVendorDefinition)
	assert.Equal(t, uint32(14122), WISPrVendorDefinition.ID)
	assert.Equal(t, "WISPr", WISPrVendorDefinition.Name)
	assert.NotEmpty(t, WISPrVendorDefinition.Attributes)

	// Check known WISPr attributes
	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range WISPrVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify WISPr-Location-Id exists
	locationID, exists := attrMap["WISPr-Location-Id"]
	assert.True(t, exists, "WISPr-Location-Id should exist")
	if exists {
		assert.Equal(t, uint32(1), locationID.ID)
		assert.Equal(t, DataTypeString, locationID.DataType)
	}

	// Verify WISPr-Bandwidth-Min-Up exists
	bandwidthMinUp, exists := attrMap["WISPr-Bandwidth-Min-Up"]
	assert.True(t, exists, "WISPr-Bandwidth-Min-Up should exist")
	if exists {
		assert.Equal(t, uint32(5), bandwidthMinUp.ID)
		assert.Equal(t, DataTypeInteger, bandwidthMinUp.DataType)
	}

	// Verify all 9 attributes exist
	assert.Len(t, WISPrVendorDefinition.Attributes, 9)
}

func TestNoDuplicateWISPrAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range WISPrVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate WISPr attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}
