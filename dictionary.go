package goradius

import (
	"fmt"
	"strings"
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

	// childParentByName maps a container child's globally-unique name to its
	// parent (top-level) attribute. This lets the flat packet interface address
	// struct/tlv/evs members by their own name without nesting.
	childParentByName map[string]*AttributeDefinition
}

// childParent resolves a flat child name to its parent attribute definition.
func (d *Dictionary) childParent(name string) (*AttributeDefinition, bool) {
	d.mu.RLock()
	parent, ok := d.childParentByName[name]
	d.mu.RUnlock()
	return parent, ok
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
		childParentByName:  make(map[string]*AttributeDefinition),
	}
}

// indexChildren records every child (recursively) of a top-level attribute in
// childParentByName, pointing at the top-level parent so flat child names
// resolve to the attribute that owns them.
func (d *Dictionary) indexChildren(top *AttributeDefinition) {
	var walk func(attr *AttributeDefinition)
	walk = func(attr *AttributeDefinition) {
		for _, child := range attr.Children {
			d.childParentByName[child.Name] = top
			walk(child)
		}
	}
	walk(top)
}

// validateAttributeDefinition validates that attribute names and value keys are lowercase,
// that every attribute carries a non-zero ID, and recursively validates child
// attributes, rejecting duplicate child IDs within a parent.
func validateAttributeDefinition(attr *AttributeDefinition) error {
	if attr.Name != strings.ToLower(attr.Name) {
		return fmt.Errorf("attribute name %q must be lowercase", attr.Name)
	}

	// ID is required and must be non-zero: RADIUS attribute types and vendor
	// sub-types are 1-255, and struct/tlv/evs children use a 1-based index.
	// A zero ID is the unset zero value and is never valid.
	if attr.ID == 0 {
		return fmt.Errorf("attribute %q has no ID (ID is required and must be non-zero)", attr.Name)
	}

	for key := range attr.Values {
		if key != strings.ToLower(key) {
			return fmt.Errorf("attribute %q value key %q must be lowercase", attr.Name, key)
		}
	}

	// Every child must carry a unique ID within its parent. For tlv/evs
	// children the ID is the on-wire sub-type; for struct members it is the
	// 1-based positional index. A missing ID (the zero value) collides and is
	// rejected, which guards against definitions that forget to set it.
	seenChildIDs := make(map[uint32]string, len(attr.Children))
	seenChildNames := make(map[string]struct{}, len(attr.Children))
	for _, child := range attr.Children {
		if existing, exists := seenChildIDs[child.ID]; exists {
			return fmt.Errorf("attribute %q has duplicate child ID %d: %q and %q", attr.Name, child.ID, existing, child.Name)
		}
		seenChildIDs[child.ID] = child.Name

		if _, exists := seenChildNames[child.Name]; exists {
			return fmt.Errorf("attribute %q has duplicate child name %q", attr.Name, child.Name)
		}
		seenChildNames[child.Name] = struct{}{}

		if err := validateAttributeDefinition(child); err != nil {
			return err
		}
	}

	return nil
}

// validateBatch validates a batch of attribute definitions before insertion:
// each definition must be valid, must not conflict with an already-registered
// attribute name, and must not duplicate a name or ID within the batch itself.
// Every attribute name must be globally flat-unique, including nested children
// (struct members and tlv/evs sub-attributes), so a child name cannot shadow a
// top-level attribute or another parent's child.
func validateBatch(attrs []*AttributeDefinition, existingByName map[string]*AttributeDefinition) error {
	seenNames := make(map[string]struct{}, len(attrs))
	seenIDs := make(map[uint32]struct{}, len(attrs))

	// checkName enforces flat name uniqueness for an attribute and, recursively,
	// its children against both the already-registered names and this batch.
	checkName := func(name string) error {
		if _, exists := existingByName[name]; exists {
			return fmt.Errorf("duplicate attribute name %q: already exists", name)
		}
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf("duplicate attribute name %q within batch", name)
		}
		seenNames[name] = struct{}{}
		return nil
	}

	var checkChildrenNames func(attr *AttributeDefinition) error
	checkChildrenNames = func(attr *AttributeDefinition) error {
		for _, child := range attr.Children {
			if err := checkName(child.Name); err != nil {
				return err
			}
			if err := checkChildrenNames(child); err != nil {
				return err
			}
		}
		return nil
	}

	for _, attr := range attrs {
		if err := validateAttributeDefinition(attr); err != nil {
			return err
		}

		if err := checkName(attr.Name); err != nil {
			return err
		}
		if err := checkChildrenNames(attr); err != nil {
			return err
		}

		if _, exists := seenIDs[attr.ID]; exists {
			return fmt.Errorf("duplicate attribute ID %d within batch", attr.ID)
		}
		seenIDs[attr.ID] = struct{}{}
	}

	return nil
}

// AddStandardAttributes adds standard RFC attributes to the
// Returns an error if any attribute name conflicts with existing standard or vendor attributes.
// Attribute names and value keys must be lowercase only.
func (d *Dictionary) AddStandardAttributes(attrs []*AttributeDefinition) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := validateBatch(attrs, d.allAttrByName); err != nil {
		return err
	}

	// Enforce global ID uniqueness across standard attributes so a second call
	// cannot silently overwrite an already-registered attribute ID.
	for _, attr := range attrs {
		if prev, dup := d.standardByID[attr.ID]; dup {
			return fmt.Errorf("duplicate standard attribute ID %d: %q and %q", attr.ID, prev.Name, attr.Name)
		}
	}

	// All checks passed, add the attributes
	for _, attr := range attrs {
		d.standardByID[attr.ID] = attr
		d.standardByName[attr.Name] = attr
		d.allAttrByName[attr.Name] = attr
		d.indexChildren(attr)
	}

	return nil
}

// AddVendor adds a vendor and its attributes to the
// Returns an error if any vendor attribute name conflicts with existing standard or vendor attributes,
// or if a (vendor-id, attr-id) pair is already registered.
func (d *Dictionary) AddVendor(vendor *VendorDefinition) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := validateBatch(vendor.Attributes, d.allAttrByName); err != nil {
		return err
	}

	// Enforce global uniqueness of the (vendor-id, attr-id) pair across every
	// vendor definition already registered, so a repeated vendor ID or a split
	// definition cannot silently overwrite an existing attribute.
	if existing := d.vendorAttrByID[vendor.ID]; existing != nil {
		for _, attr := range vendor.Attributes {
			if prev, dup := existing[attr.ID]; dup {
				return fmt.Errorf("duplicate vendor attribute (vendor %d, id %d): %q and %q", vendor.ID, attr.ID, prev.Name, attr.Name)
			}
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
		d.indexChildren(attr)
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

// GetAllAttributes returns all attributes in the dictionary (both standard and vendor)
func (d *Dictionary) GetAllAttributes() []*AttributeDefinition {
	d.mu.RLock()
	defer d.mu.RUnlock()

	attrs := make([]*AttributeDefinition, 0, len(d.allAttrByName))
	for _, attr := range d.allAttrByName {
		attrs = append(attrs, attr)
	}
	return attrs
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
