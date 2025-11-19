package dictionary

import (
	"fmt"
	"testing"
)

func BenchmarkLookupStandardByID(b *testing.B) {
	dict := New()
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
	dict := New()
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
	dict := New()

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
	dict := New()

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
	dict := New()

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
		dict := New()
		attrs := make([]*AttributeDefinition, 50)
		for j := 0; j < 50; j++ {
			attrs[j] = &AttributeDefinition{
				ID:       uint32(j + 1),
				Name:     fmt.Sprintf("Attr-%d", j+1),
				DataType: DataTypeString,
			}
		}
		vendor := &VendorDefinition{
			ID:         4874,
			Name:       "TestVendor",
			Attributes: attrs,
		}
		dict.AddVendor(vendor)
	}
}

func BenchmarkAddStandardAttributes(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		dict := New()
		attrs := make([]*AttributeDefinition, 100)
		for j := 0; j < 100; j++ {
			attrs[j] = &AttributeDefinition{
				ID:       uint32(j + 1),
				Name:     fmt.Sprintf("Attr-%d", j+1),
				DataType: DataTypeString,
			}
		}
		dict.AddStandardAttributes(attrs)
	}
}
