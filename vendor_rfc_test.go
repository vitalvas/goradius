package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStandardRFCAttributes(t *testing.T) {
	assert.NotNil(t, StandardRFCAttributes)
	assert.NotEmpty(t, StandardRFCAttributes)

	// Check some well-known attributes
	nameMap := make(map[string]*AttributeDefinition)
	idMap := make(map[uint32]*AttributeDefinition)

	for _, attr := range StandardRFCAttributes {
		nameMap[attr.Name] = attr
		idMap[attr.ID] = attr
	}

	// Verify User-Name (ID 1)
	userNameAttr, exists := idMap[1]
	assert.True(t, exists, "user-name attribute should exist")
	if exists {
		assert.Equal(t, "user-name", userNameAttr.Name)
		assert.Equal(t, DataTypeString, userNameAttr.DataType)
	}

	// Verify User-Password (ID 2)
	userPassAttr, exists := idMap[2]
	assert.True(t, exists, "user-password attribute should exist")
	if exists {
		assert.Equal(t, "user-password", userPassAttr.Name)
		assert.Equal(t, DataTypeString, userPassAttr.DataType)
		assert.Equal(t, EncryptionUserPassword, userPassAttr.Encryption)
	}

	// Verify NAS-IP-Address (ID 4)
	nasIPAttr, exists := idMap[4]
	assert.True(t, exists, "nas-ip-address attribute should exist")
	if exists {
		assert.Equal(t, "nas-ip-address", nasIPAttr.Name)
		assert.Equal(t, DataTypeIPAddr, nasIPAttr.DataType)
	}

	// Verify Framed-IP-Address (ID 8)
	framedIPAttr, exists := idMap[8]
	assert.True(t, exists, "framed-ip-address attribute should exist")
	if exists {
		assert.Equal(t, "framed-ip-address", framedIPAttr.Name)
		assert.Equal(t, DataTypeIPAddr, framedIPAttr.DataType)
	}
}

func TestNoDuplicateStandardAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range StandardRFCAttributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestNoDuplicateStandardAttributeNames(t *testing.T) {
	seen := make(map[string]uint32)

	for _, attr := range StandardRFCAttributes {
		if existing, exists := seen[attr.Name]; exists {
			t.Errorf("Duplicate attribute name %s: ID %d and %d", attr.Name, existing, attr.ID)
		}
		seen[attr.Name] = attr.ID
	}
}
