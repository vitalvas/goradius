package dictionary

import "fmt"

// Common attribute lookup helpers

// GetAttributeTypeByName returns the attribute type for a given name
func (d *Dictionary) GetAttributeTypeByName(name string) (uint8, error) {
	attr, found := d.GetAttributeByName(name)
	if !found {
		return 0, fmt.Errorf("attribute '%s' not found in dictionary", name)
	}
	return attr.ID, nil
}

// GetAttributeNameByType returns the attribute name for a given type
func (d *Dictionary) GetAttributeNameByType(attrType uint8) string {
	if attr, found := d.GetAttribute(attrType); found {
		return attr.Name
	}
	return fmt.Sprintf("Attr-%d", attrType)
}

// Common attribute type lookups for convenience
var (
// Standard RFC attribute lookup functions will be created as needed
)
