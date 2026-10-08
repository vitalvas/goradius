package goradius

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewDictionary(t *testing.T) {
	dict := NewDictionary()
	assert.NotNil(t, dict)
	assert.NotNil(t, dict.standardByID)
	assert.NotNil(t, dict.standardByName)
	assert.NotNil(t, dict.vendorByID)
	assert.NotNil(t, dict.vendorAttrByID)
	assert.NotNil(t, dict.allAttrByName)
	assert.NotNil(t, dict.attrNameToVendorID)
}

func TestAddStandardAttributes(t *testing.T) {
	dict := NewDictionary()

	attrs := []*AttributeDefinition{
		{
			ID:       1,
			Name:     "user-name",
			DataType: DataTypeString,
		},
		{
			ID:         2,
			Name:       "user-password",
			DataType:   DataTypeString,
			Encryption: EncryptionUserPassword,
		},
		{
			ID:       4,
			Name:     "nas-ip-address",
			DataType: DataTypeIPAddr,
		},
	}

	require.NoError(t, dict.AddStandardAttributes(attrs))

	// Verify lookup by ID
	attr, exists := dict.LookupStandardByID(1)
	assert.True(t, exists)
	assert.Equal(t, "user-name", attr.Name)

	// Verify lookup by name
	attr, exists = dict.LookupStandardByName("user-password")
	assert.True(t, exists)
	assert.Equal(t, uint32(2), attr.ID)
	assert.Equal(t, EncryptionUserPassword, attr.Encryption)
}

func TestLookupStandardByID(t *testing.T) {
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
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
	dict := NewDictionary()
	dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
	})

	tests := []struct {
		name     string
		attrName string
		exists   bool
	}{
		{"existing attribute", "user-name", true},
		{"non-existing attribute", "NonExistent", false},
		{"case sensitive", "User-Name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exists := dict.LookupStandardByName(tt.attrName)
			assert.Equal(t, tt.exists, exists)
		})
	}
}

func TestAddVendor(t *testing.T) {
	dict := NewDictionary()

	vendor := &VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{
				ID:       1,
				Name:     "erx-service-activate",
				DataType: DataTypeString,
				HasTag:   true,
			},
			{
				ID:       13,
				Name:     "erx-primary-dns",
				DataType: DataTypeIPAddr,
			},
		},
	}

	require.NoError(t, dict.AddVendor(vendor))

	// Verify vendor lookup
	v, exists := dict.LookupVendorByID(4874)
	assert.True(t, exists)
	assert.Equal(t, "erx", v.Name)
	assert.Len(t, v.Attributes, 2)

	// Verify vendor attribute lookup by ID
	attr, exists := dict.LookupVendorAttributeByID(4874, 1)
	assert.True(t, exists)
	assert.Equal(t, "erx-service-activate", attr.Name)
	assert.True(t, attr.HasTag)

	// Verify vendor attribute lookup by name (using unified lookup)
	attr, exists = dict.LookupByAttributeName("erx-primary-dns")
	assert.True(t, exists)
	assert.Equal(t, uint32(13), attr.ID)
	assert.Equal(t, DataTypeIPAddr, attr.DataType)
}

func TestLookupVendorByID(t *testing.T) {
	dict := NewDictionary()
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
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
	dict := NewDictionary()
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "test-attr", DataType: DataTypeString},
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

func TestLookupByAttributeName(t *testing.T) {
	dict := NewDictionary()
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "test-attr", DataType: DataTypeString},
		},
	})

	tests := []struct {
		name     string
		attrName string
		exists   bool
	}{
		{"existing vendor attribute", "test-attr", true},
		{"non-existent attribute", "NonExistent", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, exists := dict.LookupByAttributeName(tt.attrName)
			assert.Equal(t, tt.exists, exists)
		})
	}
}

func TestGetAllAttributes(t *testing.T) {
	dict := NewDictionary()

	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
		{ID: 2, Name: "user-password", DataType: DataTypeString},
	}))

	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "erx-primary-dns", DataType: DataTypeIPAddr},
		},
	}))

	attrs := dict.GetAllAttributes()
	assert.Len(t, attrs, 3)

	names := make(map[string]bool)
	for _, attr := range attrs {
		names[attr.Name] = true
	}
	assert.True(t, names["user-name"])
	assert.True(t, names["user-password"])
	assert.True(t, names["erx-primary-dns"])
}

func TestGetAllAttributesEmpty(t *testing.T) {
	dict := NewDictionary()
	attrs := dict.GetAllAttributes()
	assert.Empty(t, attrs)
}

func TestGetAllVendors(t *testing.T) {
	dict := NewDictionary()

	require.NoError(t, dict.AddVendor(&VendorDefinition{ID: 4874, Name: "erx"}))
	require.NoError(t, dict.AddVendor(&VendorDefinition{ID: 9, Name: "cisco"}))
	require.NoError(t, dict.AddVendor(&VendorDefinition{ID: 529, Name: "ascend"}))

	vendors := dict.GetAllVendors()
	assert.Len(t, vendors, 3)

	// Check that all vendors are present
	names := make(map[string]bool)
	for _, v := range vendors {
		names[v.Name] = true
	}
	assert.True(t, names["erx"])
	assert.True(t, names["cisco"])
	assert.True(t, names["ascend"])
}

func TestMultipleVendorsSameAttribute(t *testing.T) {
	dict := NewDictionary()

	// Add two vendors with same attribute ID but different vendor IDs
	dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "erx-attr", DataType: DataTypeString},
		},
	})

	dict.AddVendor(&VendorDefinition{
		ID:   9,
		Name: "cisco",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "cisco-attr", DataType: DataTypeString},
		},
	})

	// Both should be retrievable
	erxAttr, exists := dict.LookupVendorAttributeByID(4874, 1)
	assert.True(t, exists)
	assert.Equal(t, "erx-attr", erxAttr.Name)

	ciscoAttr, exists := dict.LookupVendorAttributeByID(9, 1)
	assert.True(t, exists)
	assert.Equal(t, "cisco-attr", ciscoAttr.Name)
}

func TestAttributeWithEnumeratedValues(t *testing.T) {
	dict := NewDictionary()

	dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       6,
			Name:     "service-type",
			DataType: DataTypeInteger,
			Values: map[string]uint32{
				"login":    1,
				"framed":   2,
				"callback": 3,
			},
		},
	})

	attr, exists := dict.LookupStandardByID(6)
	assert.True(t, exists)
	assert.NotNil(t, attr.Values)
	assert.Equal(t, uint32(1), attr.Values["login"])
	assert.Equal(t, uint32(2), attr.Values["framed"])
	assert.Equal(t, uint32(3), attr.Values["callback"])
}

func TestAttributeWithTag(t *testing.T) {
	dict := NewDictionary()

	dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:       64,
			Name:     "tunnel-type",
			DataType: DataTypeInteger,
			HasTag:   true,
		},
	})

	attr, exists := dict.LookupStandardByID(64)
	assert.True(t, exists)
	assert.True(t, attr.HasTag)
}

func TestAttributeWithEncryption(t *testing.T) {
	dict := NewDictionary()

	dict.AddStandardAttributes([]*AttributeDefinition{
		{
			ID:         2,
			Name:       "user-password",
			DataType:   DataTypeString,
			Encryption: EncryptionUserPassword,
		},
		{
			ID:         69,
			Name:       "tunnel-password",
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
	dict := NewDictionary()

	_, exists := dict.LookupStandardByID(1)
	assert.False(t, exists)

	_, exists = dict.LookupStandardByName("user-name")
	assert.False(t, exists)

	vendors := dict.GetAllVendors()
	assert.Empty(t, vendors)
}

func TestDuplicateStandardAttributeName(t *testing.T) {
	dict := NewDictionary()

	// Add initial standard attributes
	attrs1 := []*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
		{ID: 2, Name: "user-password", DataType: DataTypeString},
	}
	require.NoError(t, dict.AddStandardAttributes(attrs1))

	// Try to add duplicate standard attribute name
	attrs2 := []*AttributeDefinition{
		{ID: 3, Name: "user-name", DataType: DataTypeString}, // Duplicate!
	}
	err := dict.AddStandardAttributes(attrs2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "user-name")
}

func TestStandardAttributeConflictsWithVendorAttribute(t *testing.T) {
	dict := NewDictionary()

	// Add vendor with attribute first
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "test-attribute", DataType: DataTypeString},
		},
	}))

	// Try to add standard attribute with same name
	attrs := []*AttributeDefinition{
		{ID: 1, Name: "test-attribute", DataType: DataTypeString}, // Conflicts!
	}
	err := dict.AddStandardAttributes(attrs)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "test-attribute")
}

func TestDuplicateVendorAttributeName(t *testing.T) {
	dict := NewDictionary()

	// Add first vendor
	require.NoError(t, dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "shared-attribute", DataType: DataTypeString},
		},
	}))

	// Try to add second vendor with same attribute name
	err := dict.AddVendor(&VendorDefinition{
		ID:   9,
		Name: "cisco",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "shared-attribute", DataType: DataTypeString}, // Duplicate!
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "shared-attribute")
}

func TestVendorAttributeConflictsWithStandardAttribute(t *testing.T) {
	dict := NewDictionary()

	// Add standard attribute first
	attrs := []*AttributeDefinition{
		{ID: 1, Name: "user-name", DataType: DataTypeString},
	}
	require.NoError(t, dict.AddStandardAttributes(attrs))

	// Try to add vendor attribute with same name
	err := dict.AddVendor(&VendorDefinition{
		ID:   4874,
		Name: "erx",
		Attributes: []*AttributeDefinition{
			{ID: 1, Name: "user-name", DataType: DataTypeString}, // Conflicts!
		},
	})
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate attribute name")
	assert.Contains(t, err.Error(), "user-name")
}

func TestAttributeNameMustBeLowercase(t *testing.T) {
	t.Run("standard attribute rejects uppercase", func(t *testing.T) {
		dict := NewDictionary()

		err := dict.AddStandardAttributes([]*AttributeDefinition{
			{ID: 1, Name: "User-Name", DataType: DataTypeString},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be lowercase")
	})

	t.Run("vendor attribute rejects uppercase", func(t *testing.T) {
		dict := NewDictionary()

		err := dict.AddVendor(&VendorDefinition{
			ID:   4874,
			Name: "erx",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "ERX-Primary-Dns", DataType: DataTypeIPAddr},
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be lowercase")
	})

	t.Run("standard attribute accepts lowercase", func(t *testing.T) {
		dict := NewDictionary()

		err := dict.AddStandardAttributes([]*AttributeDefinition{
			{ID: 1, Name: "user-name", DataType: DataTypeString},
		})
		assert.NoError(t, err)
	})

	t.Run("vendor attribute accepts lowercase", func(t *testing.T) {
		dict := NewDictionary()

		err := dict.AddVendor(&VendorDefinition{
			ID:   4874,
			Name: "erx",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "erx-primary-dns", DataType: DataTypeIPAddr},
			},
		})
		assert.NoError(t, err)
	})

	t.Run("standard attribute rejects uppercase value key", func(t *testing.T) {
		dict := NewDictionary()

		err := dict.AddStandardAttributes([]*AttributeDefinition{
			{
				ID:       6,
				Name:     "service-type",
				DataType: DataTypeInteger,
				Values: map[string]uint32{
					"Login-User": 1,
				},
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "value key")
		assert.Contains(t, err.Error(), "must be lowercase")
	})

	t.Run("vendor attribute rejects uppercase value key", func(t *testing.T) {
		dict := NewDictionary()

		err := dict.AddVendor(&VendorDefinition{
			ID:   4874,
			Name: "erx",
			Attributes: []*AttributeDefinition{
				{
					ID:       12,
					Name:     "erx-ingress-statistics",
					DataType: DataTypeInteger,
					Values: map[string]uint32{
						"Disable": 0,
					},
				},
			},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "value key")
		assert.Contains(t, err.Error(), "must be lowercase")
	})

	t.Run("accepts lowercase value keys", func(t *testing.T) {
		dict := NewDictionary()

		err := dict.AddStandardAttributes([]*AttributeDefinition{
			{
				ID:       6,
				Name:     "service-type",
				DataType: DataTypeInteger,
				Values: map[string]uint32{
					"login-user":  1,
					"framed-user": 2,
				},
			},
		})
		assert.NoError(t, err)
	})
}

func TestAttributeUsage(t *testing.T) {
	dict := NewDictionary()

	attrs := []*AttributeDefinition{
		{
			ID:       1,
			Name:     "user-name",
			DataType: DataTypeString,
			Usage:    UsageAll, // Can be used in both requests and replies
		},
		{
			ID:       2,
			Name:     "user-password",
			DataType: DataTypeString,
			Usage:    UsageAllRequests, // Only in requests
		},
		{
			ID:       8,
			Name:     "framed-ip-address",
			DataType: DataTypeIPAddr,
			Usage:    UsageAllResponses, // Only in replies
		},
		{
			ID:       4,
			Name:     "nas-ip-address",
			DataType: DataTypeIPAddr,
			// Usage not specified - defaults to unrestricted (0)
		},
	}

	require.NoError(t, dict.AddStandardAttributes(attrs))

	// Verify User-Name allows everything
	attr, exists := dict.LookupStandardByID(1)
	assert.True(t, exists)
	assert.Equal(t, UsageAll, attr.Usage)

	// Verify User-Password is request only
	attr, exists = dict.LookupStandardByID(2)
	assert.True(t, exists)
	assert.Equal(t, UsageAllRequests, attr.Usage)

	// Verify Framed-IP-Address is response only
	attr, exists = dict.LookupStandardByID(8)
	assert.True(t, exists)
	assert.Equal(t, UsageAllResponses, attr.Usage)

	// Verify NAS-IP-Address defaults to unrestricted (0)
	attr, exists = dict.LookupStandardByID(4)
	assert.True(t, exists)
	assert.Equal(t, AttributeUsage(0), attr.Usage)
}

func TestVendorAttributeUsage(t *testing.T) {
	dict := NewDictionary()

	vendor := &VendorDefinition{
		ID:   2636,
		Name: "juniper",
		Attributes: []*AttributeDefinition{
			{
				ID:       1,
				Name:     "juniper-local-user-name",
				DataType: DataTypeString,
				Usage:    UsageAllResponses, // Reply only
			},
			{
				ID:       10,
				Name:     "juniper-user-permissions",
				DataType: DataTypeString,
				Usage:    UsageAllRequests, // Request only
			},
		},
	}

	require.NoError(t, dict.AddVendor(vendor))

	// Verify Juniper-Local-User-Name is reply only
	attr, exists := dict.LookupVendorAttributeByID(2636, 1)
	assert.True(t, exists)
	assert.Equal(t, UsageAllResponses, attr.Usage)

	// Verify Juniper-User-Permissions is request only
	attr, exists = dict.LookupVendorAttributeByID(2636, 10)
	assert.True(t, exists)
	assert.Equal(t, UsageAllRequests, attr.Usage)
}

func TestAttributeChildren(t *testing.T) {
	parent := &AttributeDefinition{
		ID:       1,
		Name:     "cisco-tlv",
		DataType: DataTypeTLV,
		Children: []*AttributeDefinition{
			{ID: 1, Name: "cisco-tlv-sub-string", DataType: DataTypeString},
			{ID: 2, Name: "cisco-tlv-sub-integer", DataType: DataTypeInteger},
		},
	}

	t.Run("lookup child by ID", func(t *testing.T) {
		child, ok := parent.LookupChildByID(2)
		require.True(t, ok)
		assert.Equal(t, "cisco-tlv-sub-integer", child.Name)
		assert.Equal(t, DataTypeInteger, child.DataType)
	})

	t.Run("lookup child by name", func(t *testing.T) {
		child, ok := parent.LookupChildByName("cisco-tlv-sub-string")
		require.True(t, ok)
		assert.Equal(t, uint32(1), child.ID)
	})

	t.Run("lookup missing child by ID", func(t *testing.T) {
		_, ok := parent.LookupChildByID(99)
		assert.False(t, ok)
	})

	t.Run("lookup missing child by name", func(t *testing.T) {
		_, ok := parent.LookupChildByName("nope")
		assert.False(t, ok)
	})
}

func TestAddVendorWithChildren(t *testing.T) {
	vendor := &VendorDefinition{
		ID:   9,
		Name: "cisco-test",
		Attributes: []*AttributeDefinition{
			{
				ID:       10,
				Name:     "cisco-test-tlv",
				DataType: DataTypeTLV,
				Children: []*AttributeDefinition{
					{ID: 1, Name: "cisco-test-child-a", DataType: DataTypeString},
					{ID: 2, Name: "cisco-test-child-b", DataType: DataTypeInteger},
				},
			},
		},
	}

	require.NoError(t, validateAttributeDefinition(vendor.Attributes[0], false))

	dict := NewDictionary()
	require.NoError(t, dict.AddVendor(vendor))

	attr, ok := dict.LookupVendorAttributeByID(9, 10)
	require.True(t, ok)
	assert.Len(t, attr.Children, 2)

	child, ok := attr.LookupChildByID(2)
	require.True(t, ok)
	assert.Equal(t, "cisco-test-child-b", child.Name)
}

func TestAddVendorDuplicateChildID(t *testing.T) {
	vendor := &VendorDefinition{
		ID:   9,
		Name: "cisco-dup",
		Attributes: []*AttributeDefinition{
			{
				ID:       10,
				Name:     "cisco-dup-tlv",
				DataType: DataTypeTLV,
				Children: []*AttributeDefinition{
					{ID: 1, Name: "cisco-dup-child-a", DataType: DataTypeString},
					{ID: 1, Name: "cisco-dup-child-b", DataType: DataTypeInteger},
				},
			},
		},
	}

	err := NewDictionary().AddVendor(vendor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate child ID")
}

func TestAddVendorRequiresAttributeID(t *testing.T) {
	t.Run("top-level attribute without id", func(t *testing.T) {
		err := NewDictionary().AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-noid",
			Attributes: []*AttributeDefinition{
				{Name: "cisco-noid-attr", DataType: DataTypeString}, // ID defaults to 0
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID is required")
	})

	t.Run("struct child without id", func(t *testing.T) {
		err := NewDictionary().AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-childnoid",
			Attributes: []*AttributeDefinition{
				{
					ID:       10,
					Name:     "cisco-childnoid-struct",
					DataType: DataTypeStruct,
					Children: []*AttributeDefinition{
						{Name: "cisco-childnoid-member", DataType: DataTypeByte}, // ID defaults to 0
					},
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID is required")
	})

	t.Run("standard attribute without id", func(t *testing.T) {
		err := NewDictionary().AddStandardAttributes([]*AttributeDefinition{
			{Name: "noid-standard", DataType: DataTypeString}, // ID defaults to 0
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ID is required")
	})
}

func TestAddVendorFlatChildNameUniqueness(t *testing.T) {
	t.Run("child name collides with top-level attribute", func(t *testing.T) {
		err := NewDictionary().AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-flat-a",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "cisco-flat-shared", DataType: DataTypeString},
				{
					ID:       2,
					Name:     "cisco-flat-struct",
					DataType: DataTypeStruct,
					Children: []*AttributeDefinition{
						{ID: 1, Name: "cisco-flat-shared", DataType: DataTypeByte}, // collides with attr 1
					},
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate attribute name")
	})

	t.Run("child name collides across different parents", func(t *testing.T) {
		err := NewDictionary().AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-flat-b",
			Attributes: []*AttributeDefinition{
				{
					ID:       1,
					Name:     "cisco-flat-s1",
					DataType: DataTypeStruct,
					Children: []*AttributeDefinition{
						{ID: 1, Name: "cisco-flat-member", DataType: DataTypeByte},
					},
				},
				{
					ID:       2,
					Name:     "cisco-flat-s2",
					DataType: DataTypeStruct,
					Children: []*AttributeDefinition{
						{ID: 1, Name: "cisco-flat-member", DataType: DataTypeByte}, // same name, other parent
					},
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate attribute name")
	})

	t.Run("child name collides with existing registered attribute", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-flat-c",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "cisco-flat-existing", DataType: DataTypeString},
			},
		}))
		err := dict.AddVendor(&VendorDefinition{
			ID:   10,
			Name: "cisco-flat-d",
			Attributes: []*AttributeDefinition{
				{
					ID:       1,
					Name:     "cisco-flat-parent",
					DataType: DataTypeStruct,
					Children: []*AttributeDefinition{
						{ID: 1, Name: "cisco-flat-existing", DataType: DataTypeByte}, // already registered
					},
				},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already exists")
	})
}

func TestAddVendorDuplicateVendorAttrID(t *testing.T) {
	t.Run("same vendor id across two calls", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-a",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "cisco-a-first", DataType: DataTypeString},
			},
		}))
		// A second definition reusing vendor 9 and attr-id 1 must be rejected,
		// not silently overwrite the first.
		err := dict.AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-b",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "cisco-b-second", DataType: DataTypeString},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate vendor attribute")
	})

	t.Run("distinct attr ids under same vendor id are allowed", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-c",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "cisco-c-first", DataType: DataTypeString},
			},
		}))
		require.NoError(t, dict.AddVendor(&VendorDefinition{
			ID:   9,
			Name: "cisco-d",
			Attributes: []*AttributeDefinition{
				{ID: 2, Name: "cisco-d-second", DataType: DataTypeString},
			},
		}))
	})
}

func TestAddStandardAttributesDuplicateIDAcrossCalls(t *testing.T) {
	dict := NewDictionary()
	require.NoError(t, dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 200, Name: "std-first", DataType: DataTypeString},
	}))
	err := dict.AddStandardAttributes([]*AttributeDefinition{
		{ID: 200, Name: "std-second", DataType: DataTypeInteger},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate standard attribute ID")
}

func TestAddStandardAttributesDuplicateWithinBatch(t *testing.T) {
	t.Run("duplicate name", func(t *testing.T) {
		err := NewDictionary().AddStandardAttributes([]*AttributeDefinition{
			{ID: 1, Name: "dup-name", DataType: DataTypeString},
			{ID: 2, Name: "dup-name", DataType: DataTypeInteger},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate attribute name")
	})

	t.Run("duplicate ID", func(t *testing.T) {
		err := NewDictionary().AddStandardAttributes([]*AttributeDefinition{
			{ID: 1, Name: "name-a", DataType: DataTypeString},
			{ID: 1, Name: "name-b", DataType: DataTypeInteger},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate attribute ID")
	})
}

func TestAddVendorDuplicateWithinBatch(t *testing.T) {
	t.Run("duplicate name", func(t *testing.T) {
		err := NewDictionary().AddVendor(&VendorDefinition{
			ID:   9,
			Name: "dup-vendor",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "dup-attr", DataType: DataTypeString},
				{ID: 2, Name: "dup-attr", DataType: DataTypeInteger},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate attribute name")
	})

	t.Run("duplicate ID", func(t *testing.T) {
		err := NewDictionary().AddVendor(&VendorDefinition{
			ID:   9,
			Name: "dup-vendor",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "attr-a", DataType: DataTypeString},
				{ID: 1, Name: "attr-b", DataType: DataTypeInteger},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "duplicate attribute ID")
	})
}

func TestAddVendorDuplicateChildName(t *testing.T) {
	vendor := &VendorDefinition{
		ID:   9,
		Name: "childdup",
		Attributes: []*AttributeDefinition{
			{
				ID:       10,
				Name:     "childdup-tlv",
				DataType: DataTypeTLV,
				Children: []*AttributeDefinition{
					{ID: 1, Name: "dup-child", DataType: DataTypeString},
					{ID: 2, Name: "dup-child", DataType: DataTypeInteger},
				},
			},
		},
	}

	err := NewDictionary().AddVendor(vendor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate child name")
}

func TestAddVendorChildNameMustBeLowercase(t *testing.T) {
	vendor := &VendorDefinition{
		ID:   9,
		Name: "cisco-case",
		Attributes: []*AttributeDefinition{
			{
				ID:       10,
				Name:     "cisco-case-tlv",
				DataType: DataTypeTLV,
				Children: []*AttributeDefinition{
					{ID: 1, Name: "Cisco-Case-Child", DataType: DataTypeString},
				},
			},
		},
	}

	err := NewDictionary().AddVendor(vendor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be lowercase")
}

func BenchmarkLookupStandardByID(b *testing.B) {
	dict := NewDictionary()
	attrs := make([]*AttributeDefinition, 100)
	for i := 0; i < 100; i++ {
		attrs[i] = &AttributeDefinition{
			ID:       uint32(i + 1),
			Name:     fmt.Sprintf("Attr-%d", i+1),
			DataType: DataTypeString,
		}
	}
	dict.AddStandardAttributes(attrs)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = dict.LookupStandardByID(50)
		}
	})
}

func BenchmarkLookupStandardByName(b *testing.B) {
	dict := NewDictionary()
	attrs := make([]*AttributeDefinition, 100)
	for i := 0; i < 100; i++ {
		attrs[i] = &AttributeDefinition{
			ID:       uint32(i + 1),
			Name:     fmt.Sprintf("Attr-%d", i+1),
			DataType: DataTypeString,
		}
	}
	dict.AddStandardAttributes(attrs)

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = dict.LookupStandardByName("Attr-50")
		}
	})
}

func BenchmarkLookupVendorAttributeByID(b *testing.B) {
	dict := NewDictionary()

	// Add 10 vendors with 50 attributes each
	for v := 0; v < 10; v++ {
		attrs := make([]*AttributeDefinition, 50)
		for i := 0; i < 50; i++ {
			attrs[i] = &AttributeDefinition{
				ID:       uint32(i + 1),
				Name:     fmt.Sprintf("Vendor%d-Attr-%d", v, i+1),
				DataType: DataTypeString,
			}
		}
		vendor := &VendorDefinition{
			ID:         uint32(1000 + v),
			Name:       fmt.Sprintf("Vendor-%d", v),
			Attributes: attrs,
		}
		dict.AddVendor(vendor)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = dict.LookupVendorAttributeByID(1005, 25)
		}
	})
}

func BenchmarkLookupByAttributeName(b *testing.B) {
	dict := NewDictionary()

	// Add 10 vendors with 50 attributes each
	for v := 0; v < 10; v++ {
		attrs := make([]*AttributeDefinition, 50)
		for i := 0; i < 50; i++ {
			attrs[i] = &AttributeDefinition{
				ID:       uint32(i + 1),
				Name:     fmt.Sprintf("Vendor%d-Attr-%d", v, i+1),
				DataType: DataTypeString,
			}
		}
		vendor := &VendorDefinition{
			ID:         uint32(1000 + v),
			Name:       fmt.Sprintf("Vendor-%d", v),
			Attributes: attrs,
		}
		dict.AddVendor(vendor)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = dict.LookupByAttributeName("Vendor5-Attr-25")
		}
	})
}

func BenchmarkGetAllVendors(b *testing.B) {
	dict := NewDictionary()

	// Add 10 vendors
	for v := 0; v < 10; v++ {
		vendor := &VendorDefinition{
			ID:         uint32(1000 + v),
			Name:       fmt.Sprintf("Vendor-%d", v),
			Attributes: []*AttributeDefinition{},
		}
		dict.AddVendor(vendor)
	}

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = dict.GetAllVendors()
		}
	})
}

func BenchmarkAddVendor(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dict := NewDictionary()
		attrs := make([]*AttributeDefinition, 50)
		for j := 0; j < 50; j++ {
			attrs[j] = &AttributeDefinition{
				ID:       uint32(j + 1),
				Name:     fmt.Sprintf("attr-%d", j+1),
				DataType: DataTypeString,
			}
		}
		vendor := &VendorDefinition{
			ID:         4874,
			Name:       "testvendor",
			Attributes: attrs,
		}
		dict.AddVendor(vendor)
	}
}

func BenchmarkAddStandardAttributes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dict := NewDictionary()
		attrs := make([]*AttributeDefinition, 100)
		for j := 0; j < 100; j++ {
			attrs[j] = &AttributeDefinition{
				ID:       uint32(j + 1),
				Name:     fmt.Sprintf("attr-%d", j+1),
				DataType: DataTypeString,
			}
		}
		dict.AddStandardAttributes(attrs)
	}
}

func TestChildNameUniquenessAcrossCalls(t *testing.T) {
	tlvWithChild := func(vendorAttrID uint32, attrName, childName string) *AttributeDefinition {
		return &AttributeDefinition{
			ID:       vendorAttrID,
			Name:     attrName,
			DataType: DataTypeTLV,
			Children: []*AttributeDefinition{
				{ID: 1, Name: childName, DataType: DataTypeString},
			},
		}
	}

	t.Run("child name conflicting with an earlier call's child is rejected", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddVendor(&VendorDefinition{
			ID:         1001,
			Name:       "vendor-a",
			Attributes: []*AttributeDefinition{tlvWithChild(1, "va-container", "shared-child-name")},
		}))

		err := dict.AddVendor(&VendorDefinition{
			ID:         1002,
			Name:       "vendor-b",
			Attributes: []*AttributeDefinition{tlvWithChild(1, "vb-container", "shared-child-name")},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already a child")
	})

	t.Run("top-level name conflicting with an earlier call's child is rejected", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddVendor(&VendorDefinition{
			ID:         1001,
			Name:       "vendor-a",
			Attributes: []*AttributeDefinition{tlvWithChild(1, "va-container", "va-child")},
		}))

		err := dict.AddStandardAttributes([]*AttributeDefinition{
			{ID: 240, Name: "va-child", DataType: DataTypeString},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "already a child")
	})
}

func TestAddVendorSplitRegistration(t *testing.T) {
	t.Run("merged definition lists attributes from every call", func(t *testing.T) {
		dict := NewDictionary()
		first := &VendorDefinition{
			ID:   2001,
			Name: "split-vendor",
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "split-first", DataType: DataTypeString},
			},
		}
		second := &VendorDefinition{
			ID:   2001,
			Name: "split-vendor",
			Attributes: []*AttributeDefinition{
				{ID: 2, Name: "split-second", DataType: DataTypeString},
			},
		}
		require.NoError(t, dict.AddVendor(first))
		require.NoError(t, dict.AddVendor(second))

		merged, ok := dict.LookupVendorByID(2001)
		require.True(t, ok)
		assert.Len(t, merged.Attributes, 2)

		// The caller-supplied definitions are not mutated by the merge.
		assert.Len(t, first.Attributes, 1)
		assert.Len(t, second.Attributes, 1)
	})

	t.Run("VSA format mismatch across calls is rejected", func(t *testing.T) {
		dict := NewDictionary()
		require.NoError(t, dict.AddVendor(&VendorDefinition{
			ID:           2002,
			Name:         "fmt-vendor",
			TypeOctets:   2,
			LengthOctets: 1,
			Attributes: []*AttributeDefinition{
				{ID: 1, Name: "fmt-first", DataType: DataTypeString},
			},
		}))

		err := dict.AddVendor(&VendorDefinition{
			ID:   2002,
			Name: "fmt-vendor",
			Attributes: []*AttributeDefinition{
				{ID: 2, Name: "fmt-second", DataType: DataTypeString},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "VSA format")
	})
}
