package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	dict := New()
	assert.NotNil(t, dict)
	assert.NotNil(t, dict.standardByID)
	assert.NotNil(t, dict.standardByName)
	assert.NotNil(t, dict.vendorByID)
	assert.NotNil(t, dict.vendorAttrByID)
	assert.NotNil(t, dict.vendorAttrByName)
}

func TestAddStandardAttributes(t *testing.T) {
	dict := New()

	attrs := []*AttributeDefinition{
		{
			ID:       1,
			Name:     "User-Name",
			DataType: DataTypeString,
		},
		{
			ID:       2,
			Name:     "User-Password",
			DataType: DataTypeString,
			Encryption: EncryptionUserPassword,
		},
		{
			ID:       4,
			Name:     "NAS-IP-Address",
			DataType: DataTypeIPAddr,
		},
	}

	require.NoError(t, dict.AddStandardAttributes(attrs))

	// Verify lookup by ID
	attr, exists := dict.LookupStandardByID(1)
	assert.True(t, exists)
	assert.Equal(t, "User-Name", attr.Name)

	// Verify lookup by name
	attr, exists = dict.LookupStandardByName("User-Password")
	assert.True(t, exists)
	assert.Equal(t, uint32(2), attr.ID)
	assert.Equal(t, EncryptionUserPassword, attr.Encryption)
}

func TestLookupStandardByID(t *testing.T) {
	dict := New()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "User-Name", DataType: DataTypeString},
	})

	tests := []struct {
		name   string
		id     uint32
		exists bool
	}{
		{"existing attribute", 1, true},
		{"non-existing attribute", 99, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exists := dict.LookupStandardByID(tt.id)
			assert.Equal(t, tt.exists, exists)
		})
	}
}

func TestLookupStandardByName(t *testing.T) {
	dict := New()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "User-Name", DataType: DataTypeString},
	})

	tests := []struct {
		name   string
		attrName string
		exists bool
	}{
		{"existing attribute", "User-Name", true},
		{"non-existing attribute", "NonExistent", false},
		{"case sensitive", "user-name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exists := dict.LookupStandardByName(tt.attrName)
			assert.Equal(t, tt.exists, exists)
		})
	}
}

func TestAddVendor(t *testing.T) {
	dict := New()

	vendor := &VendorDefinition{
		ID:          4874,
		Name:        "ERX",
		Description: "Juniper ERX",
		Attributes: []*AttributeDefinition{
			{
				ID:       1,
				Name:     "ERX-Service-Activate",
				DataType: DataTypeString,
				HasTag:   true,
			},
			{
				ID:       13,
				Name:     "ERX-Primary-Dns",
				DataType: DataTypeIPAddr,
			},
		},
	}

	require.NoError(t, dict.AddVendor(vendor))

	// Verify vendor lookup
	v, exists := dict.LookupVendorByID(4874)
	assert.True(t, exists)
	assert.Equal(t, "ERX", v.Name)
	assert.Len(t, v.Attributes, 2)

	// Verify vendor attribute lookup by ID
	attr, exists := dict.LookupVendorAttributeByID(4874, 1)
	assert.True(t, exists)
	assert.Equal(t, "ERX-Service-Activate", attr.Name)
	assert.True(t, attr.HasTag)

	// Verify vendor attribute lookup by name
	attr, exists = dict.LookupVendorAttributeByName("ERX", "ERX-Primary-Dns")
	assert.True(t, exists)
	assert.Equal(t, uint32(13), attr.ID)
	assert.Equal(t, DataTypeIPAddr, attr.DataType)
}

func TestLookupVendorByID(t *testing.T) {
	dict := New()
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "ERX",
	})

	tests := []struct {
		name   string
		id     uint32
		exists bool
	}{
		{"existing vendor", 4874, true},
		{"non-existing vendor", 9999, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exists := dict.LookupVendorByID(tt.id)
			assert.Equal(t, tt.exists, exists)
		})
	}
}

func TestLookupVendorAttributeByID(t *testing.T) {
	dict := New()
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "Test-Attr", DataType: DataTypeString},
		},
	})

	tests := []struct {
		name     string
		vendorID uint32
		attrID   uint32
		exists   bool
	}{
		{"existing attribute", 4874, 1, true},
		{"wrong vendor", 9999, 1, false},
		{"wrong attribute", 4874, 99, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exists := dict.LookupVendorAttributeByID(tt.vendorID, tt.attrID)
			assert.Equal(t, tt.exists, exists)
		})
	}
}

func TestLookupVendorAttributeByName(t *testing.T) {
	dict := New()
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "Test-Attr", DataType: DataTypeString},
		},
	})

	tests := []struct {
		name       string
		vendorName string
		attrName   string
		exists     bool
	}{
		{"existing attribute", "ERX", "Test-Attr", true},
		{"wrong vendor", "Cisco", "Test-Attr", false},
		{"wrong attribute", "ERX", "NonExistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exists := dict.LookupVendorAttributeByName(tt.vendorName, tt.attrName)
			assert.Equal(t, tt.exists, exists)
		})
	}
}

func TestGetAllVendors(t *testing.T) {
	dict := New()

	require.NoError(t, dict.AddVendor(&VendorDefinition{ID: 4874, Name: "ERX"}))
	require.NoError(t, dict.AddVendor(&VendorDefinition{ID: 9, Name: "Cisco"}))
	require.NoError(t, dict.AddVendor(&VendorDefinition{ID: 529, Name: "Ascend"}))

	vendors := dict.GetAllVendors()
	assert.Len(t, vendors, 3)

	// Check that all vendors are present
	names := make(map[string]bool)
	for _, v := range vendors {
		names[v.Name] = true
	}
	assert.True(t, names["ERX"])
	assert.True(t, names["Cisco"])
	assert.True(t, names["Ascend"])
}

func TestMultipleVendorsSameAttribute(t *testing.T) {
	dict := New()

	// Add two vendors with same attribute ID but different vendor IDs
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "ERX-Attr", DataType: DataTypeString},
		},
	})

	dict.AddVendor(&VendorDefinition{
		ID:   9,
		Name: "Cisco",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "Cisco-Attr", DataType: DataTypeString},
		},
	})

	// Both should be retrievable
	erxAttr, exists := dict.LookupVendorAttributeByID(4874, 1)
	assert.True(t, exists)
	assert.Equal(t, "ERX-Attr", erxAttr.Name)

	ciscoAttr, exists := dict.LookupVendorAttributeByID(9, 1)
	assert.True(t, exists)
	assert.Equal(t, "Cisco-Attr", ciscoAttr.Name)
}

func TestAttributeWithEnumeratedValues(t *testing.T) {
	dict := New()

	dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       6,
			Name:     "Service-Type",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"Login":  1,
				"Framed": 2,
				"Callback": 3,
			},
		},
	})

	attr, exists := dict.LookupStandardByID(6)
	assert.True(t, exists)
	assert.NotNil(t, attr.Values)
	assert.Equal(t, uint32(1), attr.Values["Login"])
	assert.Equal(t, uint32(2), attr.Values["Framed"])
	assert.Equal(t, uint32(3), attr.Values["Callback"])
}

func TestAttributeWithTag(t *testing.T) {
	dict := New()

	dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       64,
			Name:     "Tunnel-Type",
			DataType: DataTypeInteger,
			HasTag:   true,
		},
	})

	attr, exists := dict.LookupStandardByID(64)
	assert.True(t, exists)
	assert.True(t, attr.HasTag)
}

func TestAttributeWithEncryption(t *testing.T) {
	dict := New()

	dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:         2,
			Name:       "User-Password",
			DataType:   DataTypeString,
			Encryption: EncryptionUserPassword,
		},
		{
			ID:         69,
			Name:       "Tunnel-Password",
			DataType:   DataTypeString,
			Encryption: EncryptionTunnelPassword,
		},
	})

	userPassAttr, _ := dict.LookupStandardByID(2)
	assert.Equal(t, EncryptionUserPassword, userPassAttr.Encryption)

	tunnelPassAttr, _ := dict.LookupStandardByID(69)
	assert.Equal(t, EncryptionTunnelPassword, tunnelPassAttr.Encryption)
}

func TestEmptyDictionary(t *testing.T) {
	dict := New()

	_, exists := dict.LookupStandardByID(1)
	assert.False(t, exists)

	_, exists = dict.LookupStandardByName("User-Name")
	assert.False(t, exists)

	vendors := dict.GetAllVendors()
	assert.Empty(t, vendors)
}

func TestDuplicateStandardAttributeName(t *testing.T) {
	dict := New()

	// Add initial standard attributes
	attrs1 := []*AttributeDefinition{
		{ID: 1, Name: "User-Name", DataType: DataTypeString},
		{ID: 2, Name: "User-Password", DataType: DataTypeString},
	}
	require.NoError(t, dict.AddStandardAttributes(attrs1))

	// Try to add duplicate standard attribute name
	attrs2 := []*AttributeDefinition{
		{ID: 3, Name: "User-Name", DataType: DataTypeString}, // Duplicate!
	}
	err := dict.AddStandardAttributes(attrs2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "User-Name")
}

func TestStandardAttributeConflictsWithVendorAttribute(t *testing.T) {
	dict := New()

	// Add vendor with attribute first
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "Test-Attribute", DataType: DataTypeString},
		},
	}))

	// Try to add standard attribute with same name
	attrs := []*AttributeDefinition{
		{ID: 1, Name: "Test-Attribute", DataType: DataTypeString}, // Conflicts with ERX!
	}
	err := dict.AddStandardAttributes(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "Test-Attribute")
	assert.Contains(t, err.Error(), "vendor ERX")
}

func TestDuplicateVendorAttributeName(t *testing.T) {
	dict := New()

	// Add first vendor
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "Shared-Attribute", DataType: DataTypeString},
		},
	}))

	// Try to add second vendor with same attribute name
	err := dict.AddVendor(&VendorDefinition{
		ID:   9,
		Name: "Cisco",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "Shared-Attribute", DataType: DataTypeString}, // Duplicate!
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "Shared-Attribute")
	assert.Contains(t, err.Error(), "vendor ERX")
}

func TestVendorAttributeConflictsWithStandardAttribute(t *testing.T) {
	dict := New()

	// Add standard attribute first
	attrs := []*AttributeDefinition{
		{ID: 1, Name: "User-Name", DataType: DataTypeString},
	}
	require.NoError(t, dict.AddStandardAttributes(attrs))

	// Try to add vendor attribute with same name
	err := dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "ERX",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "User-Name", DataType: DataTypeString}, // Conflicts with standard!
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "User-Name")
	assert.Contains(t, err.Error(), "standard attribute")
}
