package dictionary

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// ArrayValue represents a single value in an array attribute
type ArrayValue struct {
	Value []byte
	Index int // Optional index for ordered arrays
}

// ArrayAttribute represents an array of attribute values
type ArrayAttribute struct {
	Definition *AttributeDefinition
	Values     []ArrayValue
}

// NewArrayAttribute creates a new array attribute
func NewArrayAttribute(definition *AttributeDefinition) *ArrayAttribute {
	if !definition.Array {
		return nil
	}

	return &ArrayAttribute{
		Definition: definition,
		Values:     make([]ArrayValue, 0),
	}
}

// AddValue adds a value to the array attribute
func (aa *ArrayAttribute) AddValue(value []byte) error {
	if !aa.Definition.Array {
		return fmt.Errorf("attribute %s is not an array", aa.Definition.Name)
	}

	// Validate the value
	if err := aa.Definition.ValidateValue(value); err != nil {
		return fmt.Errorf("invalid value for array attribute %s: %w", aa.Definition.Name, err)
	}

	arrayValue := ArrayValue{
		Value: value,
		Index: len(aa.Values),
	}

	aa.Values = append(aa.Values, arrayValue)
	return nil
}

// AddValueWithIndex adds a value at a specific index
func (aa *ArrayAttribute) AddValueWithIndex(value []byte, index int) error {
	if !aa.Definition.Array {
		return fmt.Errorf("attribute %s is not an array", aa.Definition.Name)
	}

	if index < 0 {
		return fmt.Errorf("array index cannot be negative")
	}

	// Validate the value
	if err := aa.Definition.ValidateValue(value); err != nil {
		return fmt.Errorf("invalid value for array attribute %s: %w", aa.Definition.Name, err)
	}

	arrayValue := ArrayValue{
		Value: value,
		Index: index,
	}

	aa.Values = append(aa.Values, arrayValue)
	return nil
}

// GetValues returns all values in the array
func (aa *ArrayAttribute) GetValues() [][]byte {
	values := make([][]byte, len(aa.Values))
	for i, av := range aa.Values {
		values[i] = av.Value
	}
	return values
}

// GetValueAtIndex returns the value at a specific index
func (aa *ArrayAttribute) GetValueAtIndex(index int) ([]byte, bool) {
	for _, av := range aa.Values {
		if av.Index == index {
			return av.Value, true
		}
	}
	return nil, false
}

// GetSortedValues returns values sorted by index
func (aa *ArrayAttribute) GetSortedValues() []ArrayValue {
	sorted := make([]ArrayValue, len(aa.Values))
	copy(sorted, aa.Values)

	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Index < sorted[j].Index
	})

	return sorted
}

// Length returns the number of values in the array
func (aa *ArrayAttribute) Length() int {
	return len(aa.Values)
}

// IsEmpty returns true if the array has no values
func (aa *ArrayAttribute) IsEmpty() bool {
	return len(aa.Values) == 0
}

// Clear removes all values from the array
func (aa *ArrayAttribute) Clear() {
	aa.Values = aa.Values[:0]
}

// RemoveValue removes a value from the array
func (aa *ArrayAttribute) RemoveValue(value []byte) bool {
	for i, av := range aa.Values {
		if string(av.Value) == string(value) {
			aa.Values = append(aa.Values[:i], aa.Values[i+1:]...)
			return true
		}
	}
	return false
}

// RemoveValueAtIndex removes a value at a specific index
func (aa *ArrayAttribute) RemoveValueAtIndex(index int) bool {
	for i, av := range aa.Values {
		if av.Index == index {
			aa.Values = append(aa.Values[:i], aa.Values[i+1:]...)
			return true
		}
	}
	return false
}

// HasValue checks if a value exists in the array
func (aa *ArrayAttribute) HasValue(value []byte) bool {
	for _, av := range aa.Values {
		if string(av.Value) == string(value) {
			return true
		}
	}
	return false
}

// FormatValues formats all values for display
func (aa *ArrayAttribute) FormatValues() []string {
	formatted := make([]string, len(aa.Values))
	for i, av := range aa.Values {
		formatted[i] = aa.Definition.FormatValue(av.Value)
	}
	return formatted
}

// String returns a string representation of the array attribute
func (aa *ArrayAttribute) String() string {
	if aa.IsEmpty() {
		return fmt.Sprintf("%s: []", aa.Definition.Name)
	}

	formatted := aa.FormatValues()
	return fmt.Sprintf("%s: [%s]", aa.Definition.Name, strings.Join(formatted, ", "))
}

// ArrayCollection manages multiple array attributes
type ArrayCollection struct {
	arrays map[string]*ArrayAttribute
}

// NewArrayCollection creates a new array collection
func NewArrayCollection() *ArrayCollection {
	return &ArrayCollection{
		arrays: make(map[string]*ArrayAttribute),
	}
}

// GetArray returns an array attribute by name
func (ac *ArrayCollection) GetArray(name string) (*ArrayAttribute, bool) {
	array, exists := ac.arrays[name]
	return array, exists
}

// CreateArray creates a new array attribute
func (ac *ArrayCollection) CreateArray(definition *AttributeDefinition) (*ArrayAttribute, error) {
	if !definition.Array {
		return nil, fmt.Errorf("attribute %s is not defined as an array", definition.Name)
	}

	array := NewArrayAttribute(definition)
	if array == nil {
		return nil, fmt.Errorf("failed to create array for attribute %s", definition.Name)
	}

	ac.arrays[definition.Name] = array
	return array, nil
}

// AddValueToArray adds a value to an array attribute
func (ac *ArrayCollection) AddValueToArray(name string, value []byte) error {
	array, exists := ac.arrays[name]
	if !exists {
		return fmt.Errorf("array attribute %s not found", name)
	}

	return array.AddValue(value)
}

// GetArrayNames returns all array attribute names
func (ac *ArrayCollection) GetArrayNames() []string {
	names := make([]string, 0, len(ac.arrays))
	for name := range ac.arrays {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// GetAllArrays returns all array attributes
func (ac *ArrayCollection) GetAllArrays() map[string]*ArrayAttribute {
	result := make(map[string]*ArrayAttribute)
	for name, array := range ac.arrays {
		result[name] = array
	}
	return result
}

// RemoveArray removes an array attribute
func (ac *ArrayCollection) RemoveArray(name string) bool {
	_, exists := ac.arrays[name]
	if exists {
		delete(ac.arrays, name)
	}
	return exists
}

// Clear removes all array attributes
func (ac *ArrayCollection) Clear() {
	ac.arrays = make(map[string]*ArrayAttribute)
}

// Enhanced attribute definition methods for arrays

// ValidateArrayValue validates a value for an array attribute
func (attr *AttributeDefinition) ValidateArrayValue(value []byte) error {
	if !attr.Array {
		return fmt.Errorf("attribute %s is not an array", attr.Name)
	}

	return attr.ValidateValue(value)
}

// ParseArrayValues parses string values into array values
func (attr *AttributeDefinition) ParseArrayValues(values []string) ([][]byte, error) {
	if !attr.Array {
		return nil, fmt.Errorf("attribute %s is not an array", attr.Name)
	}

	result := make([][]byte, len(values))
	for i, valueStr := range values {
		value, err := attr.ParseValue(valueStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse array value %d: %w", i, err)
		}
		result[i] = value
	}

	return result, nil
}

// GetArrayValueConstraints returns constraints for array values
func (attr *AttributeDefinition) GetArrayValueConstraints() map[string]interface{} {
	constraints := make(map[string]interface{})

	constraints["is_array"] = attr.Array
	constraints["data_type"] = attr.DataType
	constraints["min_length"] = attr.GetMinimumLength()
	constraints["max_length"] = attr.GetMaximumLength()
	constraints["fixed_length"] = attr.IsFixedLength()
	constraints["has_values"] = attr.HasValues()

	if attr.HasValues() {
		constraints["allowed_values"] = attr.Values
	}

	return constraints
}

// ArrayAttributeBuilder helps build array attributes
type ArrayAttributeBuilder struct {
	definition *AttributeDefinition
	values     []ArrayValue
}

// NewArrayAttributeBuilder creates a new array attribute builder
func NewArrayAttributeBuilder(definition *AttributeDefinition) (*ArrayAttributeBuilder, error) {
	if !definition.Array {
		return nil, fmt.Errorf("attribute %s is not an array", definition.Name)
	}

	return &ArrayAttributeBuilder{
		definition: definition,
		values:     make([]ArrayValue, 0),
	}, nil
}

// AddStringValue adds a string value to the array
func (aab *ArrayAttributeBuilder) AddStringValue(value string) error {
	parsedValue, err := aab.definition.ParseValue(value)
	if err != nil {
		return fmt.Errorf("failed to parse string value: %w", err)
	}

	arrayValue := ArrayValue{
		Value: parsedValue,
		Index: len(aab.values),
	}

	aab.values = append(aab.values, arrayValue)
	return nil
}

// AddStringValueWithIndex adds a string value at a specific index
func (aab *ArrayAttributeBuilder) AddStringValueWithIndex(value string, index int) error {
	parsedValue, err := aab.definition.ParseValue(value)
	if err != nil {
		return fmt.Errorf("failed to parse string value: %w", err)
	}

	arrayValue := ArrayValue{
		Value: parsedValue,
		Index: index,
	}

	aab.values = append(aab.values, arrayValue)
	return nil
}

// AddRawValue adds a raw byte value to the array
func (aab *ArrayAttributeBuilder) AddRawValue(value []byte) error {
	if err := aab.definition.ValidateValue(value); err != nil {
		return fmt.Errorf("invalid raw value: %w", err)
	}

	arrayValue := ArrayValue{
		Value: value,
		Index: len(aab.values),
	}

	aab.values = append(aab.values, arrayValue)
	return nil
}

// AddMultipleStringValues adds multiple string values
func (aab *ArrayAttributeBuilder) AddMultipleStringValues(values []string) error {
	for i, value := range values {
		parsedValue, err := aab.definition.ParseValue(value)
		if err != nil {
			return fmt.Errorf("failed to parse string value %d: %w", i, err)
		}

		arrayValue := ArrayValue{
			Value: parsedValue,
			Index: len(aab.values),
		}

		aab.values = append(aab.values, arrayValue)
	}
	return nil
}

// AddFromCSV adds values from a CSV string
func (aab *ArrayAttributeBuilder) AddFromCSV(csv string) error {
	values := strings.Split(csv, ",")
	for i, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if err := aab.AddStringValue(value); err != nil {
			return fmt.Errorf("failed to add CSV value %d: %w", i, err)
		}
	}
	return nil
}

// AddFromIndexedString adds values from indexed string format (e.g., "1:value1,2:value2")
func (aab *ArrayAttributeBuilder) AddFromIndexedString(indexed string) error {
	pairs := strings.Split(indexed, ",")
	for i, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("invalid indexed format at position %d: %s", i, pair)
		}

		index, err := strconv.Atoi(strings.TrimSpace(parts[0]))
		if err != nil {
			return fmt.Errorf("invalid index at position %d: %w", i, err)
		}

		value := strings.TrimSpace(parts[1])
		if err := aab.AddStringValueWithIndex(value, index); err != nil {
			return fmt.Errorf("failed to add indexed value %d: %w", i, err)
		}
	}
	return nil
}

// Build creates the final array attribute
func (aab *ArrayAttributeBuilder) Build() *ArrayAttribute {
	return &ArrayAttribute{
		Definition: aab.definition,
		Values:     aab.values,
	}
}

// Reset clears all values from the builder
func (aab *ArrayAttributeBuilder) Reset() {
	aab.values = aab.values[:0]
}

// GetValueCount returns the number of values in the builder
func (aab *ArrayAttributeBuilder) GetValueCount() int {
	return len(aab.values)
}

// Array utility functions

// MergeArrayAttributes merges multiple array attributes with the same definition
func MergeArrayAttributes(arrays ...*ArrayAttribute) (*ArrayAttribute, error) {
	if len(arrays) == 0 {
		return nil, fmt.Errorf("no arrays to merge")
	}

	// Check that all arrays have the same definition
	definition := arrays[0].Definition
	for i, array := range arrays {
		if array.Definition.Name != definition.Name {
			return nil, fmt.Errorf("array %d has different definition name: %s != %s",
				i, array.Definition.Name, definition.Name)
		}
	}

	merged := NewArrayAttribute(definition)
	if merged == nil {
		return nil, fmt.Errorf("failed to create merged array")
	}

	// Merge all values
	for _, array := range arrays {
		merged.Values = append(merged.Values, array.Values...)
	}

	return merged, nil
}

// DeduplicateArrayValues removes duplicate values from an array attribute
func DeduplicateArrayValues(array *ArrayAttribute) *ArrayAttribute {
	if array.IsEmpty() {
		return array
	}

	seen := make(map[string]bool)
	deduplicated := make([]ArrayValue, 0, len(array.Values))

	for _, value := range array.Values {
		key := string(value.Value)
		if !seen[key] {
			seen[key] = true
			deduplicated = append(deduplicated, value)
		}
	}

	return &ArrayAttribute{
		Definition: array.Definition,
		Values:     deduplicated,
	}
}

// SplitArrayAttribute splits an array attribute into multiple arrays by a delimiter
func SplitArrayAttribute(array *ArrayAttribute, delimiter byte) ([]*ArrayAttribute, error) {
	if array.Definition.DataType != DataTypeString && array.Definition.DataType != DataTypeOctets {
		return nil, fmt.Errorf("can only split string or octets arrays")
	}

	var result []*ArrayAttribute

	for _, value := range array.Values {
		parts := strings.Split(string(value.Value), string(delimiter))

		subArray := NewArrayAttribute(array.Definition)
		if subArray == nil {
			return nil, fmt.Errorf("failed to create sub-array")
		}

		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part != "" {
				if err := subArray.AddValue([]byte(part)); err != nil {
					return nil, fmt.Errorf("failed to add split value: %w", err)
				}
			}
		}

		if !subArray.IsEmpty() {
			result = append(result, subArray)
		}
	}

	return result, nil
}
