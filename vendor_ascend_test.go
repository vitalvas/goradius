package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAscendVendorDefinition(t *testing.T) {
	assert.NotNil(t, AscendVendorDefinition)
	assert.Equal(t, uint32(529), AscendVendorDefinition.ID)
	assert.Equal(t, "Ascend", AscendVendorDefinition.Name)
	assert.NotEmpty(t, AscendVendorDefinition.Attributes)

	// Verify vendor has attributes
	assert.Greater(t, len(AscendVendorDefinition.Attributes), 0)
}

func TestNoDuplicateAscendAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range AscendVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Ascend attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}
