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
		ID:          4874,
		Name:        "erx",
		Description: "Juniper ERX",
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
				"Login":    1,
				"Framed":   2,
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
}

func TestAttributeType(t *testing.T) {
	dict := NewDictionary()

	attrs := []*AttributeDefinition{
		{
			ID:       1,
			Name:     "user-name",
			DataType: DataTypeString,
			Type:     AttributeTypeRequestReply, // Can be used in both requests and replies
		},
		{
			ID:       2,
			Name:     "user-password",
			DataType: DataTypeString,
			Type:     AttributeTypeRequest, // Only in requests
		},
		{
			ID:       8,
			Name:     "framed-ip-address",
			DataType: DataTypeIPAddr,
			Type:     AttributeTypeReply, // Only in replies
		},
		{
			ID:       4,
			Name:     "nas-ip-address",
			DataType: DataTypeIPAddr,
			// Type not specified - should default to AttributeTypeRequestReply (0)
		},
	}

	require.NoError(t, dict.AddStandardAttributes(attrs))

	// Verify User-Name is RequestReply
	attr, exists := dict.LookupStandardByID(1)
	assert.True(t, exists)
	assert.Equal(t, AttributeTypeRequestReply, attr.Type)

	// Verify User-Password is Request only
	attr, exists = dict.LookupStandardByID(2)
	assert.True(t, exists)
	assert.Equal(t, AttributeTypeRequest, attr.Type)

	// Verify Framed-IP-Address is Reply only
	attr, exists = dict.LookupStandardByID(8)
	assert.True(t, exists)
	assert.Equal(t, AttributeTypeReply, attr.Type)

	// Verify NAS-IP-Address defaults to RequestReply (0)
	attr, exists = dict.LookupStandardByID(4)
	assert.True(t, exists)
	assert.Equal(t, AttributeTypeRequestReply, attr.Type)
}

func TestVendorAttributeType(t *testing.T) {
	dict := NewDictionary()

	vendor := &VendorDefinition{
		ID:   2636,
		Name: "juniper",
		Attributes: []*AttributeDefinition{
			{
				ID:       1,
				Name:     "juniper-local-user-name",
				DataType: DataTypeString,
				Type:     AttributeTypeReply, // Reply only
			},
			{
				ID:       10,
				Name:     "juniper-user-permissions",
				DataType: DataTypeString,
				Type:     AttributeTypeRequest, // Request only
			},
		},
	}

	require.NoError(t, dict.AddVendor(vendor))

	// Verify Juniper-Local-User-Name is Reply only
	attr, exists := dict.LookupVendorAttributeByID(2636, 1)
	assert.True(t, exists)
	assert.Equal(t, AttributeTypeReply, attr.Type)

	// Verify Juniper-User-Permissions is Request only
	attr, exists = dict.LookupVendorAttributeByID(2636, 10)
	assert.True(t, exists)
	assert.Equal(t, AttributeTypeRequest, attr.Type)
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
