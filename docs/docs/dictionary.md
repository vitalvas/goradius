# RADIUS Dictionary Usage

This guide covers how to work with RADIUS dictionaries for attribute definitions, validation, and vendor-specific attributes.

## Dictionary Overview

The dictionary system provides:
- Attribute type definitions and validation
- Vendor-specific attribute (VSA) support
- YAML-based configuration
- Runtime dictionary loading and management
- Type-safe attribute handling

## Dictionary Structure

### Basic Dictionary Format

```yaml
# radius-dictionary.yaml
version: "1.0"
name: "Standard RADIUS Dictionary"

attributes:
  - name: "User-Name"
    type: 1
    data_type: "string"
    description: "The name of the user to be authenticated"
    
  - name: "User-Password" 
    type: 2
    data_type: "string"
    encrypted: true
    description: "The password of the user"
    
  - name: "CHAP-Password"
    type: 3
    data_type: "octets"
    length: 17
    description: "CHAP encrypted password"

vendors:
  - id: 9
    name: "Cisco"
    attributes:
      - name: "Cisco-AVPair"
        type: 1
        data_type: "string"
        description: "Cisco attribute-value pair"
```

## Data Types

### Supported Data Types

```go
const (
    DataTypeString   = "string"   // Text string
    DataTypeOctets   = "octets"   // Binary data
    DataTypeInteger  = "integer"  // 32-bit integer
    DataTypeDate     = "date"     // Unix timestamp
    DataTypeIPAddr   = "ipaddr"   // IPv4 address
    DataTypeIPv6Addr = "ipv6addr" // IPv6 address
    DataTypeUint32   = "uint32"   // Unsigned 32-bit integer
    DataTypeUint64   = "uint64"   // Unsigned 64-bit integer
)
```

### Data Type Examples

```yaml
attributes:
  # String attribute
  - name: "User-Name"
    type: 1
    data_type: "string"
    max_length: 253
    
  # Integer attribute with enumerated values
  - name: "Service-Type"
    type: 6
    data_type: "integer"
    values:
      1: "Login"
      2: "Framed"
      3: "Callback-Login"
      4: "Callback-Framed"
      
  # IP address attribute
  - name: "NAS-IP-Address"
    type: 4
    data_type: "ipaddr"
    
  # Binary data attribute
  - name: "CHAP-Challenge"
    type: 60
    data_type: "octets"
    length: 16
    
  # Date/time attribute
  - name: "Event-Timestamp"
    type: 55
    data_type: "date"
```

## Loading Dictionaries

### From YAML File

```go
package main

import (
    "log"
    
    "github.com/vitalvas/goradius/pkg/dictionary"
)

func main() {
    // Load dictionary from file
    dict, err := dictionary.LoadFromFile("radius-dictionary.yaml")
    if err != nil {
        log.Fatal("Failed to load dictionary:", err)
    }
    
    // Use dictionary for attribute validation
    attr, err := dict.GetAttribute("User-Name")
    if err != nil {
        log.Fatal("Attribute not found:", err)
    }
    
    fmt.Printf("Attribute: %s, Type: %d, Data Type: %s\n", 
        attr.Name, attr.Type, attr.DataType)
}
```

### From YAML String

```go
dictYAML := `
version: "1.0"
name: "Custom Dictionary"
attributes:
  - name: "Custom-Attribute"
    type: 100
    data_type: "string"
`

dict, err := dictionary.LoadFromYAML([]byte(dictYAML))
if err != nil {
    log.Fatal("Failed to load dictionary:", err)
}
```

### Multiple Dictionary Sources

```go
// Load base dictionary
baseDict, err := dictionary.LoadFromFile("base-dictionary.yaml")
if err != nil {
    log.Fatal(err)
}

// Load vendor extensions
vendorDict, err := dictionary.LoadFromFile("vendor-dictionary.yaml")
if err != nil {
    log.Fatal(err)
}

// Merge dictionaries
merged := dictionary.Merge(baseDict, vendorDict)
```

## Using Dictionaries

### Attribute Lookup

```go
// Get attribute by name
attr, err := dict.GetAttributeByName("User-Name")
if err != nil {
    log.Printf("Attribute not found: %v", err)
}

// Get attribute by type
attr, err = dict.GetAttributeByType(1)
if err != nil {
    log.Printf("Attribute type not found: %v", err)
}

// Check if attribute exists
exists := dict.HasAttribute("User-Name")
if exists {
    fmt.Println("Attribute exists in dictionary")
}
```

### Attribute Validation

```go
// Validate attribute value
attr, _ := dict.GetAttributeByName("Service-Type")
valid := dict.ValidateValue(attr, "1")
if !valid {
    log.Printf("Invalid value for attribute")
}

// Validate with type conversion
value, err := dict.ConvertValue(attr, "Login")
if err != nil {
    log.Printf("Conversion failed: %v", err)
}
fmt.Printf("Converted value: %v\n", value)
```

### Working with Packets

```go
import "github.com/vitalvas/goradius/pkg/packet"

// Create packet with dictionary validation
req := packet.New(packet.CodeAccessRequest, 1)

// Add attribute using dictionary
err := dict.AddAttribute(req, "User-Name", "john.doe")
if err != nil {
    log.Printf("Failed to add attribute: %v", err)
}

// Validate packet attributes
errors := dict.ValidatePacket(req)
for _, err := range errors {
    log.Printf("Validation error: %v", err)
}
```

## Vendor-Specific Attributes

### Defining VSAs

```yaml
vendors:
  - id: 9
    name: "Cisco"
    attributes:
      - name: "Cisco-AVPair"
        type: 1
        data_type: "string"
        description: "Cisco attribute-value pair"
        
      - name: "Cisco-Account-Info"
        type: 250
        data_type: "string"
        
  - id: 311
    name: "Microsoft"
    attributes:
      - name: "MS-CHAP-Response"
        type: 1
        data_type: "octets"
        length: 50
        
      - name: "MS-CHAP2-Response"
        type: 25
        data_type: "octets"
        length: 50
```

### Using VSAs

```go
// Get vendor information
vendor, err := dict.GetVendor(9) // Cisco
if err != nil {
    log.Fatal("Vendor not found:", err)
}

// Get vendor-specific attribute
vsa, err := dict.GetVSA(9, 1) // Cisco AVPair
if err != nil {
    log.Fatal("VSA not found:", err)
}

// Add VSA to packet
err = dict.AddVSA(req, 9, "Cisco-AVPair", "tunnel-type=PPTP")
if err != nil {
    log.Printf("Failed to add VSA: %v", err)
}
```

### Custom VSA Encoding

```go
// Create custom VSA
vsa := dictionary.VSADefinition{
    VendorID:    9999,
    VendorName:  "Custom-Vendor",
    Type:        1,
    Name:        "Custom-VSA",
    DataType:    dictionary.DataTypeString,
    Description: "Custom vendor-specific attribute",
}

// Add to dictionary
dict.AddVSA(vsa)

// Use in packet
value := "custom-value"
vsaData := dictionary.EncodeVSA(vsa.VendorID, vsa.Type, []byte(value))
req.AddBytesAttribute(packet.AttributeVendorSpecific, vsaData)
```

## Dynamic Dictionary Management

### Runtime Dictionary Updates

```go
type DynamicDictionary struct {
    *dictionary.Dictionary
    mu sync.RWMutex
}

func (d *DynamicDictionary) AddAttribute(attr dictionary.AttributeDefinition) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    
    return d.Dictionary.AddAttribute(attr)
}

func (d *DynamicDictionary) RemoveAttribute(name string) error {
    d.mu.Lock()
    defer d.mu.Unlock()
    
    return d.Dictionary.RemoveAttribute(name)
}

func (d *DynamicDictionary) GetAttribute(name string) (dictionary.AttributeDefinition, error) {
    d.mu.RLock()
    defer d.mu.RUnlock()
    
    return d.Dictionary.GetAttributeByName(name)
}
```

### Dictionary Caching

```go
type CachedDictionary struct {
    dict  *dictionary.Dictionary
    cache map[string]dictionary.AttributeDefinition
    mu    sync.RWMutex
}

func (c *CachedDictionary) GetAttribute(name string) (dictionary.AttributeDefinition, error) {
    c.mu.RLock()
    if attr, exists := c.cache[name]; exists {
        c.mu.RUnlock()
        return attr, nil
    }
    c.mu.RUnlock()
    
    c.mu.Lock()
    defer c.mu.Unlock()
    
    attr, err := c.dict.GetAttributeByName(name)
    if err != nil {
        return attr, err
    }
    
    c.cache[name] = attr
    return attr, nil
}
```

## Custom Data Types

### Implementing Custom Types

```go
type CustomDataType struct {
    Name string
}

func (c CustomDataType) Validate(value []byte) error {
    // Custom validation logic
    if len(value) > 100 {
        return fmt.Errorf("value too long")
    }
    return nil
}

func (c CustomDataType) Convert(value string) (interface{}, error) {
    // Custom conversion logic
    return strings.ToUpper(value), nil
}

func (c CustomDataType) Encode(value interface{}) ([]byte, error) {
    // Custom encoding logic
    str, ok := value.(string)
    if !ok {
        return nil, fmt.Errorf("invalid type")
    }
    return []byte(str), nil
}
```

### Registering Custom Types

```go
// Register custom data type
dict.RegisterDataType("custom", CustomDataType{Name: "custom"})

// Use in dictionary definition
attr := dictionary.AttributeDefinition{
    Name:     "Custom-Attribute",
    Type:     200,
    DataType: "custom",
}

dict.AddAttribute(attr)
```

## Dictionary Validation

### Schema Validation

```go
func validateDictionary(dict *dictionary.Dictionary) []error {
    var errors []error
    
    // Check for duplicate attribute types
    typeMap := make(map[uint8]string)
    for _, attr := range dict.GetAllAttributes() {
        if existing, exists := typeMap[attr.Type]; exists {
            errors = append(errors, 
                fmt.Errorf("duplicate attribute type %d: %s and %s", 
                    attr.Type, existing, attr.Name))
        }
        typeMap[attr.Type] = attr.Name
    }
    
    // Validate data types
    for _, attr := range dict.GetAllAttributes() {
        if !dict.IsValidDataType(attr.DataType) {
            errors = append(errors, 
                fmt.Errorf("invalid data type %s for attribute %s", 
                    attr.DataType, attr.Name))
        }
    }
    
    return errors
}
```

### Attribute Consistency Checks

```go
func checkAttributeConsistency(dict *dictionary.Dictionary) error {
    for _, attr := range dict.GetAllAttributes() {
        // Check required fields
        if attr.Name == "" {
            return fmt.Errorf("attribute missing name")
        }
        
        if attr.Type == 0 {
            return fmt.Errorf("attribute %s missing type", attr.Name)
        }
        
        // Check data type specific constraints
        switch attr.DataType {
        case dictionary.DataTypeString:
            if attr.MaxLength > 253 {
                return fmt.Errorf("string attribute %s max length too large", attr.Name)
            }
        case dictionary.DataTypeOctets:
            if attr.Length > 253 {
                return fmt.Errorf("octets attribute %s length too large", attr.Name)
            }
        }
    }
    
    return nil
}
```

## Performance Optimization

### Efficient Dictionary Lookups

```go
type OptimizedDictionary struct {
    nameToType  map[string]uint8
    typeToName  map[uint8]string
    attributes  map[uint8]dictionary.AttributeDefinition
    vsaMap      map[uint32]map[uint8]dictionary.VSADefinition
}

func (o *OptimizedDictionary) GetAttributeByName(name string) (dictionary.AttributeDefinition, error) {
    attrType, exists := o.nameToType[name]
    if !exists {
        return dictionary.AttributeDefinition{}, fmt.Errorf("attribute not found: %s", name)
    }
    
    return o.attributes[attrType], nil
}

func (o *OptimizedDictionary) GetAttributeByType(attrType uint8) (dictionary.AttributeDefinition, error) {
    attr, exists := o.attributes[attrType]
    if !exists {
        return dictionary.AttributeDefinition{}, fmt.Errorf("attribute type not found: %d", attrType)
    }
    
    return attr, nil
}
```

### Memory-Efficient Loading

```go
func loadDictionaryStream(reader io.Reader) (*dictionary.Dictionary, error) {
    decoder := yaml.NewDecoder(reader)
    
    var partial struct {
        Attributes []dictionary.AttributeDefinition `yaml:"attributes"`
    }
    
    dict := dictionary.New()
    
    for {
        err := decoder.Decode(&partial)
        if err == io.EOF {
            break
        }
        if err != nil {
            return nil, err
        }
        
        for _, attr := range partial.Attributes {
            dict.AddAttribute(attr)
        }
        
        // Clear for next iteration
        partial.Attributes = nil
    }
    
    return dict, nil
}
```

## Testing Dictionaries

### Unit Testing

```go
func TestDictionaryLoading(t *testing.T) {
    dictYAML := `
version: "1.0"
attributes:
  - name: "Test-Attribute"
    type: 100
    data_type: "string"
`
    
    dict, err := dictionary.LoadFromYAML([]byte(dictYAML))
    assert.NoError(t, err)
    
    attr, err := dict.GetAttributeByName("Test-Attribute")
    assert.NoError(t, err)
    assert.Equal(t, uint8(100), attr.Type)
    assert.Equal(t, "string", attr.DataType)
}

func TestAttributeValidation(t *testing.T) {
    dict, _ := dictionary.LoadFromFile("test-dictionary.yaml")
    
    // Test valid value
    attr, _ := dict.GetAttributeByName("Service-Type")
    valid := dict.ValidateValue(attr, "1")
    assert.True(t, valid)
    
    // Test invalid value
    valid = dict.ValidateValue(attr, "999")
    assert.False(t, valid)
}
```

### Integration Testing

```go
func TestDictionaryWithPackets(t *testing.T) {
    dict, err := dictionary.LoadFromFile("test-dictionary.yaml")
    require.NoError(t, err)
    
    req := packet.New(packet.CodeAccessRequest, 1)
    
    // Add attributes using dictionary
    err = dict.AddAttribute(req, "User-Name", "testuser")
    assert.NoError(t, err)
    
    err = dict.AddAttribute(req, "Service-Type", "Login")
    assert.NoError(t, err)
    
    // Validate packet
    errors := dict.ValidatePacket(req)
    assert.Empty(t, errors)
}
```

## Best Practices

### Dictionary Design

1. **Consistent Naming**: Use consistent naming conventions
2. **Documentation**: Include descriptions for all attributes
3. **Validation**: Define appropriate constraints and ranges
4. **Versioning**: Use version numbers for dictionary compatibility
5. **Modular Design**: Split large dictionaries into logical modules

### Performance Considerations

1. **Lazy Loading**: Load dictionaries only when needed
2. **Caching**: Cache frequently accessed attributes
3. **Indexing**: Build efficient lookup indexes
4. **Memory Management**: Use appropriate data structures
5. **Validation Optimization**: Pre-compile validation rules

### Security Considerations

1. **Input Validation**: Validate all dictionary inputs
2. **Resource Limits**: Prevent dictionary DoS attacks
3. **Access Control**: Control dictionary modification
4. **Audit Logging**: Log dictionary changes
5. **Schema Validation**: Validate dictionary schema