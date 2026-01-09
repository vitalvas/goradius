package goradius

import (
	"fmt"
	"sync"
)

// Dictionary provides fast lookup for RADIUS attributes.
// It is safe for concurrent reads after initialization is complete.
// All Add* methods acquire write locks and should be called during initialization only.
type Dictionary struct {
	mu sync.RWMutex

	// Standard attributes indices
	standardByID   map[uint32]*AttributeDefinition
	standardByName map[string]*AttributeDefinition

	// Vendor metadata (VendorDefinition.Name is for documentation only)
	vendorByID map[uint32]*VendorDefinition

	// Vendor attributes by ID (nested maps - zero string allocation on lookup)
	vendorAttrByID map[uint32]map[uint32]*AttributeDefinition // vendorID -> attrID -> attr

	// Unified attribute lookup by name (standard + vendor attributes)
	// Vendor attribute names are globally unique, enforced in AddVendor
	allAttrByName map[string]*AttributeDefinition

	// Reverse lookup: attribute name -> vendor ID (for vendor attributes only)
	// This enables O(1) vendor lookup instead of O(n*m) iteration
	attrNameToVendorID map[string]uint32
}

// NewDictionary creates a new empty dictionary with fast lookup indices
func NewDictionary() *Dictionary {
	return &Dictionary{
		standardByID:       make(map[uint32]*AttributeDefinition),
		standardByName:     make(map[string]*AttributeDefinition),
		vendorByID:         make(map[uint32]*VendorDefinition),
		vendorAttrByID:     make(map[uint32]map[uint32]*AttributeDefinition),
		allAttrByName:      make(map[string]*AttributeDefinition),
		attrNameToVendorID: make(map[string]uint32),
	}
}

// AddStandardAttributes adds standard RFC attributes to the 
// Returns an error if any attribute name conflicts with existing standard or vendor attributes.
func (d *Dictionary) AddStandardAttributes(attrs []*AttributeDefinition) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Check for duplicates against unified attribute index
	for _, attr := range attrs {
		if _, exists := d.allAttrByName[attr.Name]; exists {
			return fmt.Errorf("duplicate attribute name %q: already exists", attr.Name)
		}
	}

	// All checks passed, add the attributes
	for _, attr := range attrs {
		d.standardByID[attr.ID] = attr
		d.standardByName[attr.Name] = attr
		d.allAttrByName[attr.Name] = attr
	}

	return nil
}

// AddVendor adds a vendor and its attributes to the 
// Returns an error if any vendor attribute name conflicts with existing standard or vendor attributes.
func (d *Dictionary) AddVendor(vendor *VendorDefinition) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	for _, attr := range vendor.Attributes {
		if _, exists := d.allAttrByName[attr.Name]; exists {
			return fmt.Errorf("duplicate attribute name %q: already exists", attr.Name)
		}
	}

	d.vendorByID[vendor.ID] = vendor

	if d.vendorAttrByID[vendor.ID] == nil {
		d.vendorAttrByID[vendor.ID] = make(map[uint32]*AttributeDefinition)
	}

	for _, attr := range vendor.Attributes {
		d.vendorAttrByID[vendor.ID][attr.ID] = attr
		d.allAttrByName[attr.Name] = attr
		d.attrNameToVendorID[attr.Name] = vendor.ID
	}

	return nil
}

// LookupStandardByID finds a standard attribute by ID
func (d *Dictionary) LookupStandardByID(id uint32) (*AttributeDefinition, bool) {
	d.mu.RLock()
	attr, exists := d.standardByID[id]
	d.mu.RUnlock()
	return attr, exists
}

// LookupStandardByName finds a standard attribute by name
func (d *Dictionary) LookupStandardByName(name string) (*AttributeDefinition, bool) {
	d.mu.RLock()
	attr, exists := d.standardByName[name]
	d.mu.RUnlock()
	return attr, exists
}

// LookupVendorByID finds a vendor by ID
func (d *Dictionary) LookupVendorByID(vendorID uint32) (*VendorDefinition, bool) {
	d.mu.RLock()
	vendor, exists := d.vendorByID[vendorID]
	d.mu.RUnlock()
	return vendor, exists
}

// LookupVendorAttributeByID finds a vendor attribute by vendor ID and attribute ID
func (d *Dictionary) LookupVendorAttributeByID(vendorID, attrID uint32) (*AttributeDefinition, bool) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	if attrs, ok := d.vendorAttrByID[vendorID]; ok {
		if attr, ok := attrs[attrID]; ok {
			return attr, true
		}
	}
	return nil, false
}

// LookupByAttributeName finds an attribute by name (works for both standard and vendor attributes)
func (d *Dictionary) LookupByAttributeName(name string) (*AttributeDefinition, bool) {
	d.mu.RLock()
	attr, exists := d.allAttrByName[name]
	d.mu.RUnlock()
	return attr, exists
}

// LookupVendorIDByAttributeName finds the vendor ID for a vendor attribute by its name.
// Returns (vendorID, true) if the attribute is a vendor attribute, or (0, false) if not found or is a standard attribute.
func (d *Dictionary) LookupVendorIDByAttributeName(name string) (uint32, bool) {
	d.mu.RLock()
	vendorID, exists := d.attrNameToVendorID[name]
	d.mu.RUnlock()
	return vendorID, exists
}

// GetAllVendors returns all vendors in the dictionary
func (d *Dictionary) GetAllVendors() []*VendorDefinition {
	d.mu.RLock()
	defer d.mu.RUnlock()

	vendors := make([]*VendorDefinition, 0, len(d.vendorByID))
	for _, vendor := range d.vendorByID {
		vendors = append(vendors, vendor)
	}
	return vendors
}
