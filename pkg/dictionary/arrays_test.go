package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewArrayAttribute(t *testing.T) {
	tests := []struct {
		name       string
		definition *AttributeDefinition
		expected   bool
	}{
		{
			name: "array attribute",
			definition: &AttributeDefinition{
				Name:     "Test-Array",
				ID:       100,
				DataType:   DataTypeString,
				Array:    true,
			},
			expected: true,
		},
		{
			name: "non-array attribute",
			definition: &AttributeDefinition{
				Name:     "Test-Single",
				ID:       101,
				DataType:   DataTypeString,
				Array:    false,
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := NewArrayAttribute(tt.definition)

			if tt.expected {
				assert.NotNil(t, result)
				assert.Equal(t, tt.definition, result.Definition)
				assert.Empty(t, result.Values)
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestArrayAttribute_AddValue(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	// Test adding valid values
	err := array.AddValue([]byte("value1"))
	assert.NoError(t, err)
	assert.Equal(t, 1, array.Length())

	err = array.AddValue([]byte("value2"))
	assert.NoError(t, err)
	assert.Equal(t, 2, array.Length())

	// Test values are stored correctly
	values := array.GetValues()
	assert.Equal(t, [][]byte{[]byte("value1"), []byte("value2")}, values)

	// Test indices are assigned correctly
	assert.Equal(t, 0, array.Values[0].Index)
	assert.Equal(t, 1, array.Values[1].Index)
}

func TestArrayAttribute_AddValueWithIndex(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	// Test adding values with specific indices
	err := array.AddValueWithIndex([]byte("value1"), 5)
	assert.NoError(t, err)

	err = array.AddValueWithIndex([]byte("value2"), 2)
	assert.NoError(t, err)

	// Test values can be retrieved by index
	value, exists := array.GetValueAtIndex(5)
	assert.True(t, exists)
	assert.Equal(t, []byte("value1"), value)

	value, exists = array.GetValueAtIndex(2)
	assert.True(t, exists)
	assert.Equal(t, []byte("value2"), value)

	// Test non-existent index
	_, exists = array.GetValueAtIndex(10)
	assert.False(t, exists)

	// Test negative index
	err = array.AddValueWithIndex([]byte("value3"), -1)
	assert.Error(t, err)
}

func TestArrayAttribute_GetSortedValues(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	// Add values in non-sequential order
	array.AddValueWithIndex([]byte("value3"), 3)
	array.AddValueWithIndex([]byte("value1"), 1)
	array.AddValueWithIndex([]byte("value5"), 5)
	array.AddValueWithIndex([]byte("value2"), 2)

	sorted := array.GetSortedValues()
	assert.Equal(t, 4, len(sorted))

	// Check values are sorted by index
	assert.Equal(t, 1, sorted[0].Index)
	assert.Equal(t, []byte("value1"), sorted[0].Value)
	assert.Equal(t, 2, sorted[1].Index)
	assert.Equal(t, []byte("value2"), sorted[1].Value)
	assert.Equal(t, 3, sorted[2].Index)
	assert.Equal(t, []byte("value3"), sorted[2].Value)
	assert.Equal(t, 5, sorted[3].Index)
	assert.Equal(t, []byte("value5"), sorted[3].Value)
}

func TestArrayAttribute_RemoveValue(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	// Add values
	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))
	array.AddValue([]byte("value3"))

	// Test removing existing value
	removed := array.RemoveValue([]byte("value2"))
	assert.True(t, removed)
	assert.Equal(t, 2, array.Length())

	values := array.GetValues()
	assert.Equal(t, [][]byte{[]byte("value1"), []byte("value3")}, values)

	// Test removing non-existent value
	removed = array.RemoveValue([]byte("nonexistent"))
	assert.False(t, removed)
	assert.Equal(t, 2, array.Length())
}

func TestArrayAttribute_HasValue(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))

	assert.True(t, array.HasValue([]byte("value1")))
	assert.True(t, array.HasValue([]byte("value2")))
	assert.False(t, array.HasValue([]byte("nonexistent")))
}

func TestArrayAttribute_FormatValues(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))

	formatted := array.FormatValues()
	assert.Equal(t, []string{"value1", "value2"}, formatted)
}

func TestArrayAttribute_String(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	// Test empty array
	assert.Equal(t, "Test-Array: []", array.String())

	// Test array with values
	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))
	assert.Equal(t, "Test-Array: [value1, value2]", array.String())
}

func TestArrayCollection(t *testing.T) {
	collection := NewArrayCollection()

	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	// Test creating array
	array, err := collection.CreateArray(definition)
	assert.NoError(t, err)
	assert.NotNil(t, array)

	// Test getting array
	retrieved, exists := collection.GetArray("Test-Array")
	assert.True(t, exists)
	assert.Equal(t, array, retrieved)

	// Test adding value to array
	err = collection.AddValueToArray("Test-Array", []byte("value1"))
	assert.NoError(t, err)

	// Test getting array names
	names := collection.GetArrayNames()
	assert.Equal(t, []string{"Test-Array"}, names)

	// Test removing array
	removed := collection.RemoveArray("Test-Array")
	assert.True(t, removed)

	_, exists = collection.GetArray("Test-Array")
	assert.False(t, exists)
}

func TestArrayAttributeBuilder(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	builder, err := NewArrayAttributeBuilder(definition)
	require.NoError(t, err)
	require.NotNil(t, builder)

	// Test adding string values
	err = builder.AddStringValue("value1")
	assert.NoError(t, err)

	err = builder.AddStringValue("value2")
	assert.NoError(t, err)

	assert.Equal(t, 2, builder.GetValueCount())

	// Test adding multiple values
	err = builder.AddMultipleStringValues([]string{"value3", "value4"})
	assert.NoError(t, err)

	assert.Equal(t, 4, builder.GetValueCount())

	// Test building array
	array := builder.Build()
	assert.NotNil(t, array)
	assert.Equal(t, 4, array.Length())

	values := array.GetValues()
	expected := [][]byte{
		[]byte("value1"),
		[]byte("value2"),
		[]byte("value3"),
		[]byte("value4"),
	}
	assert.Equal(t, expected, values)
}

func TestArrayAttributeBuilder_AddFromCSV(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	builder, err := NewArrayAttributeBuilder(definition)
	require.NoError(t, err)

	// Test CSV parsing
	err = builder.AddFromCSV("value1, value2, value3")
	assert.NoError(t, err)

	assert.Equal(t, 3, builder.GetValueCount())

	array := builder.Build()
	values := array.GetValues()
	expected := [][]byte{
		[]byte("value1"),
		[]byte("value2"),
		[]byte("value3"),
	}
	assert.Equal(t, expected, values)
}

func TestArrayAttributeBuilder_AddFromIndexedString(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	builder, err := NewArrayAttributeBuilder(definition)
	require.NoError(t, err)

	// Test indexed string parsing
	err = builder.AddFromIndexedString("1:value1, 3:value3, 2:value2")
	assert.NoError(t, err)

	assert.Equal(t, 3, builder.GetValueCount())

	array := builder.Build()

	// Check values are stored with correct indices
	value, exists := array.GetValueAtIndex(1)
	assert.True(t, exists)
	assert.Equal(t, []byte("value1"), value)

	value, exists = array.GetValueAtIndex(2)
	assert.True(t, exists)
	assert.Equal(t, []byte("value2"), value)

	value, exists = array.GetValueAtIndex(3)
	assert.True(t, exists)
	assert.Equal(t, []byte("value3"), value)
}

func TestMergeArrayAttributes(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	// Create first array
	array1 := NewArrayAttribute(definition)
	array1.AddValue([]byte("value1"))
	array1.AddValue([]byte("value2"))

	// Create second array
	array2 := NewArrayAttribute(definition)
	array2.AddValue([]byte("value3"))
	array2.AddValue([]byte("value4"))

	// Merge arrays
	merged, err := MergeArrayAttributes(array1, array2)
	assert.NoError(t, err)
	assert.NotNil(t, merged)

	assert.Equal(t, 4, merged.Length())
	values := merged.GetValues()
	expected := [][]byte{
		[]byte("value1"),
		[]byte("value2"),
		[]byte("value3"),
		[]byte("value4"),
	}
	assert.Equal(t, expected, values)
}

func TestDeduplicateArrayValues(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))
	array.AddValue([]byte("value1")) // duplicate
	array.AddValue([]byte("value3"))
	array.AddValue([]byte("value2")) // duplicate

	deduplicated := DeduplicateArrayValues(array)
	assert.Equal(t, 3, deduplicated.Length())

	values := deduplicated.GetValues()
	expected := [][]byte{
		[]byte("value1"),
		[]byte("value2"),
		[]byte("value3"),
	}
	assert.Equal(t, expected, values)
}

func TestAttributeDefinition_ValidateArrayValue(t *testing.T) {
	arrayAttr := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	nonArrayAttr := &AttributeDefinition{
		Name:     "Test-Single",
		ID:       101,
		DataType:   DataTypeString,
		Array:    false,
	}

	// Test array attribute
	err := arrayAttr.ValidateArrayValue([]byte("test"))
	assert.NoError(t, err)

	// Test non-array attribute
	err = nonArrayAttr.ValidateArrayValue([]byte("test"))
	assert.Error(t, err)
}

func TestAttributeDefinition_ParseArrayValues(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	values := []string{"value1", "value2", "value3"}
	parsed, err := definition.ParseArrayValues(values)

	assert.NoError(t, err)
	assert.Equal(t, 3, len(parsed))
	assert.Equal(t, []byte("value1"), parsed[0])
	assert.Equal(t, []byte("value2"), parsed[1])
	assert.Equal(t, []byte("value3"), parsed[2])
}

func TestAttributeDefinition_GetArrayValueConstraints(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
		Length:   10,
		Values:   map[string]uint32{"test": 1},
	}

	constraints := definition.GetArrayValueConstraints()

	assert.Equal(t, true, constraints["is_array"])
	assert.Equal(t, DataTypeString, constraints["data_type"])
	assert.Equal(t, 10, constraints["min_length"])
	assert.Equal(t, 10, constraints["max_length"])
	assert.Equal(t, true, constraints["fixed_length"])
	assert.Equal(t, true, constraints["has_values"])
	assert.Equal(t, map[string]uint32{"test": 1}, constraints["allowed_values"])
}

func TestArrayAttribute_Clear(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))
	assert.Equal(t, 2, array.Length())

	array.Clear()
	assert.Equal(t, 0, array.Length())
	assert.True(t, array.IsEmpty())
}

func TestArrayAttribute_RemoveValueAtIndex(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))
	array.AddValue([]byte("value3"))

	removed := array.RemoveValueAtIndex(1)
	assert.True(t, removed)
	assert.Equal(t, 2, array.Length())

	// Test invalid index
	removed = array.RemoveValueAtIndex(10)
	assert.False(t, removed)
}

func TestArrayCollection_GetAllArrays(t *testing.T) {
	collection := NewArrayCollection()

	definition1 := &AttributeDefinition{Name: "Array1", ID:   100, DataType:   DataTypeString, Array: true}
	definition2 := &AttributeDefinition{Name: "Array2", ID:   101, DataType:   DataTypeString, Array: true}

	collection.CreateArray(definition1)
	collection.CreateArray(definition2)

	arrays := collection.GetAllArrays()
	assert.Len(t, arrays, 2)
}

func TestArrayCollection_Clear(t *testing.T) {
	collection := NewArrayCollection()

	definition := &AttributeDefinition{Name: "Array1", ID:   100, DataType:   DataTypeString, Array: true}
	collection.CreateArray(definition)

	names := collection.GetArrayNames()
	assert.Len(t, names, 1)

	collection.Clear()
	names = collection.GetArrayNames()
	assert.Len(t, names, 0)
}

func TestArrayAttributeBuilder_AddRawValue(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeOctets,
		Array:    true,
	}

	builder, err := NewArrayAttributeBuilder(definition)
	require.NoError(t, err)
	require.NotNil(t, builder)

	builder.AddRawValue([]byte{0x01, 0x02, 0x03})
	builder.AddRawValue([]byte{0x04, 0x05, 0x06})

	array := builder.Build()
	assert.Equal(t, 2, array.Length())
}

func TestArrayAttributeBuilder_Reset(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	builder, err := NewArrayAttributeBuilder(definition)
	require.NoError(t, err)
	require.NotNil(t, builder)

	builder.AddStringValue("value1")
	builder.AddStringValue("value2")
	assert.Equal(t, 2, builder.GetValueCount())

	builder.Reset()
	assert.Equal(t, 0, builder.GetValueCount())
}

func TestSplitArrayAttribute(t *testing.T) {
	definition := &AttributeDefinition{
		Name:     "Test-Array",
		ID:       100,
		DataType:   DataTypeString,
		Array:    true,
	}

	array := NewArrayAttribute(definition)
	require.NotNil(t, array)

	array.AddValue([]byte("value1"))
	array.AddValue([]byte("value2"))
	array.AddValue([]byte("value3"))

	splits, err := SplitArrayAttribute(array, 2)
	require.NoError(t, err)
	assert.Len(t, splits, 3)
	assert.Equal(t, 1, splits[0].Length())
	assert.Equal(t, 1, splits[1].Length())
}
