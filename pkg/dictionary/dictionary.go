package dictionary

import (
	"fmt"
)

// Dictionary provides fast lookup for RADIUS attributes
type Dictionary struct {
	// Fast lookup maps for standard attributes
	standardByID   map[uint32]*AttributeDefinition
	standardByName map[string]*AttributeDefinition

	// Fast lookup maps for vendor attributes
	// vendorByID maps vendor ID to vendor definition
	vendorByID map[uint32]*VendorDefinition
	// vendorAttrByID maps "vendorID:attrID" to attribute definition
	vendorAttrByID map[string]*AttributeDefinition
	// vendorAttrByName maps "vendorName:attrName" to attribute definition
	vendorAttrByName map[string]*AttributeDefinition
}

// New creates a new empty dictionary with fast lookup indices
func New() *Dictionary {
	return &Dictionary{
		standardByID:     make(map[uint32]*AttributeDefinition),
		standardByName:   make(map[string]*AttributeDefinition),
		vendorByID:       make(map[uint32]*VendorDefinition),
		vendorAttrByID:   make(map[string]*AttributeDefinition),
		vendorAttrByName: make(map[string]*AttributeDefinition),
	}
}


// AddStandardAttributes adds standard RFC attributes to the dictionary.
// Returns an error if any attribute name conflicts with existing standard or vendor attributes.
func (d *Dictionary) AddStandardAttributes(attrs []*AttributeDefinition) error {
	// Check for duplicates within the new attributes and against existing attributes
	for _, attr := range attrs {
		// Check if name already exists in standard attributes
		if _, exists := d.standardByName[attr.Name]; exists {
			return fmt.Errorf("duplicate attribute name %q: already exists as standard attribute", attr.Name)
		}

		// Check if name conflicts with any vendor attribute
		for _, vendor := range d.vendorByID {
			for _, vendorAttr := range vendor.Attributes {
				if vendorAttr.Name == attr.Name {
					return fmt.Errorf("duplicate attribute name %q: conflicts with vendor %s attribute", attr.Name, vendor.Name)
				}
			}
		}
	}

	// All checks passed, add the attributes
	for _, attr := range attrs {
		d.standardByID[attr.ID] = attr
		d.standardByName[attr.Name] = attr
	}

	return nil
}

// AddVendor adds a vendor and its attributes to the dictionary.
// Returns an error if any vendor attribute name conflicts with existing standard or vendor attributes.
func (d *Dictionary) AddVendor(vendor *VendorDefinition) error {
	// Check for duplicates in vendor attributes against all existing attributes
	for _, attr := range vendor.Attributes {
		// Check if name conflicts with standard attributes
		if _, exists := d.standardByName[attr.Name]; exists {
			return fmt.Errorf("duplicate attribute name %q: conflicts with standard attribute", attr.Name)
		}

		// Check if name conflicts with existing vendor attributes
		for _, existingVendor := range d.vendorByID {
			for _, existingAttr := range existingVendor.Attributes {
				if existingAttr.Name == attr.Name {
					return fmt.Errorf("duplicate attribute name %q: conflicts with vendor %s attribute", attr.Name, existingVendor.Name)
				}
			}
		}
	}

	// All checks passed, add the vendor
	d.vendorByID[vendor.ID] = vendor

	for _, attr := range vendor.Attributes {
		// Create composite keys for fast lookup
		idKey := fmt.Sprintf("%d:%d", vendor.ID, attr.ID)
		nameKey := fmt.Sprintf("%s:%s", vendor.Name, attr.Name)

		d.vendorAttrByID[idKey] = attr
		d.vendorAttrByName[nameKey] = attr
	}

	return nil
}

// LookupStandardByID finds a standard attribute by ID
func (d *Dictionary) LookupStandardByID(id uint32) (*AttributeDefinition, bool) {
	attr, exists := d.standardByID[id]
	return attr, exists
}

// LookupStandardByName finds a standard attribute by name
func (d *Dictionary) LookupStandardByName(name string) (*AttributeDefinition, bool) {
	attr, exists := d.standardByName[name]
	return attr, exists
}

// LookupVendorByID finds a vendor by ID
func (d *Dictionary) LookupVendorByID(vendorID uint32) (*VendorDefinition, bool) {
	vendor, exists := d.vendorByID[vendorID]
	return vendor, exists
}

// LookupVendorAttributeByID finds a vendor attribute by vendor ID and attribute ID
func (d *Dictionary) LookupVendorAttributeByID(vendorID, attrID uint32) (*AttributeDefinition, bool) {
	key := fmt.Sprintf("%d:%d", vendorID, attrID)
	attr, exists := d.vendorAttrByID[key]
	return attr, exists
}

// LookupVendorAttributeByName finds a vendor attribute by vendor name and attribute name
func (d *Dictionary) LookupVendorAttributeByName(vendorName, attrName string) (*AttributeDefinition, bool) {
	key := fmt.Sprintf("%s:%s", vendorName, attrName)
	attr, exists := d.vendorAttrByName[key]
	return attr, exists
}

// GetAllVendors returns all vendors in the dictionary
func (d *Dictionary) GetAllVendors() []*VendorDefinition {
	vendors := make([]*VendorDefinition, 0, len(d.vendorByID))
	for _, vendor := range d.vendorByID {
		vendors = append(vendors, vendor)
	}
	return vendors
}
