# RADIUS Dictionary Usage

This guide covers how to work with RADIUS dictionaries for attribute definitions, validation, and vendor-specific attributes.

## Dictionary Overview

The dictionary system provides:
- Fast attribute lookups by ID and name
- Vendor-specific attribute (VSA) support
- In-code dictionary definitions
- Type-safe attribute handling with data type support

## Dictionary Structure

The Dictionary uses efficient map-based lookups for both standard and vendor-specific attributes.

### Creating a Dictionary

```go
import (
    "github.com/vitalvas/goradius/pkg/dictionary"
    "github.com/vitalvas/goradius/pkg/dictionaries"
)

// Create a new dictionary
dict := dictionary.New()

// Add standard RFC attributes
dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

// Add vendor definitions
dict.AddVendor(dictionaries.ERXVendorDefinition)
```

## Data Types

### Supported Data Types

```go
const (
    DataTypeString     DataType = "string"
    DataTypeOctets     DataType = "octets"
    DataTypeInteger    DataType = "integer"
    DataTypeIPAddr     DataType = "ipaddr"
    DataTypeDate       DataType = "date"
    DataTypeIPv6Addr   DataType = "ipv6addr"
    DataTypeIPv6Prefix DataType = "ipv6prefix"
    DataTypeIfID       DataType = "ifid"
    DataTypeTLV        DataType = "tlv"
    DataTypeABinary    DataType = "abinary"
)
```

### Attribute Definition Structure

```go
type AttributeDefinition struct {
    ID          uint32            // Attribute ID
    Name        string            // Attribute name
    DataType    DataType          // Data type
    Encryption  EncryptionType    // Optional encryption
    HasTag      bool              // Supports tagging (RFC 2868)
    Array       bool              // Multiple values allowed
    Values      map[string]uint32 // Enumerated values
    Description string            // Description
}
```

### Encryption Types

```go
const (
    EncryptionNone           EncryptionType = ""
    EncryptionUserPassword   EncryptionType = "user-password"
    EncryptionTunnelPassword EncryptionType = "tunnel-password"
    EncryptionAscendSecret   EncryptionType = "ascend-secret"
)
```

## Dictionary Lookups

### Lookup Standard Attributes

```go
// Lookup by ID
attr, exists := dict.LookupStandardByID(1) // User-Name
if exists {
    fmt.Printf("Attribute: %s, Data Type: %s\n", attr.Name, attr.DataType)
}

// Lookup by name
attr, exists = dict.LookupStandardByName("User-Name")
if exists {
    fmt.Printf("Attribute ID: %d, Data Type: %s\n", attr.ID, attr.DataType)
}
```

### Lookup Vendor Attributes

```go
// Lookup vendor by ID
vendor, exists := dict.LookupVendorByID(4874) // ERX vendor ID
if exists {
    fmt.Printf("Vendor: %s\n", vendor.Name)
}

// Lookup vendor attribute by IDs
attr, exists := dict.LookupVendorAttributeByID(4874, 1) // ERX vendor, attribute 1
if exists {
    fmt.Printf("Vendor Attribute: %s\n", attr.Name)
}

// Lookup vendor attribute by names
attr, exists = dict.LookupVendorAttributeByName("ERX", "ERX-Service-Activate")
if exists {
    fmt.Printf("Attribute ID: %d\n", attr.ID)
}
```

### Get All Vendors

```go
vendors := dict.GetAllVendors()
for _, vendor := range vendors {
    fmt.Printf("Vendor: %s (ID: %d)\n", vendor.Name, vendor.ID)
    for _, attr := range vendor.Attributes {
        fmt.Printf("  - %s (ID: %d, Type: %s)\n",
            attr.Name, attr.ID, attr.DataType)
    }
}
```

## Using Dictionaries with Packets

### Adding Attributes by Name

```go
import "github.com/vitalvas/goradius/pkg/packet"

// Create packet with dictionary
req := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)

// Add attribute by name
req.AddAttributeByName("User-Name", "john.doe")
req.AddAttributeByName("Framed-IP-Address", "192.0.2.11")

// Add vendor attribute by name
req.AddAttributeByName("ERX-Primary-Dns", "8.8.8.8")
```

### Adding Attributes with Encryption

```go
secret := []byte("testing123")
authenticator := req.Authenticator

// Add encrypted password
req.AddAttributeByNameWithSecret("User-Password", "secret123", secret, authenticator)

// The library handles encryption based on the attribute definition
```

### Working with Enumerated Values

```go
// If an attribute has enumerated values in the dictionary,
// you can use the string name instead of numeric value
attr := &dictionary.AttributeDefinition{
    ID:       6,
    Name:     "Service-Type",
    DataType: dictionary.DataTypeInteger,
    Values: map[string]uint32{
        "Login":  1,
        "Framed": 2,
    },
}

// Add to dictionary
dict.AddStandardAttributes([]*dictionary.AttributeDefinition{attr})

// Use enumerated value by name
req.AddAttributeByName("Service-Type", "Login") // Converts to 1
```

## Vendor-Specific Attributes

### Defining Vendor Attributes

```go
// Define vendor with attributes
vendor := &dictionary.VendorDefinition{
    ID:          4874,
    Name:        "ERX",
    Description: "Juniper ERX",
    Attributes: []*dictionary.AttributeDefinition{
        {
            ID:       1,
            Name:     "ERX-Service-Activate",
            DataType: dictionary.DataTypeString,
            HasTag:   true,
        },
        {
            ID:       13,
            Name:     "ERX-Primary-Dns",
            DataType: dictionary.DataTypeIPAddr,
        },
    },
}

// Add vendor to dictionary
dict.AddVendor(vendor)
```

### Using VSAs in Packets

```go
// Add vendor attribute by name (dictionary handles VSA encoding)
req.AddAttributeByName("ERX-Primary-Dns", "8.8.8.8")

// Add tagged vendor attribute
req.AddAttributeByName("ERX-Service-Activate:1", "ipoe-parking")
req.AddAttributeByName("ERX-Service-Activate:3", "svc-ipoe-policer(52428800, 52428800)")

// Manually create and add vendor attribute
va := packet.NewVendorAttribute(4874, 13, packet.EncodeIPAddr(net.ParseIP("8.8.8.8")))
req.AddVendorAttribute(va)

// Create tagged vendor attribute
va := packet.NewTaggedVendorAttribute(4874, 1, 1, []byte("ipoe-parking"))
req.AddVendorAttribute(va)
```

### Retrieving VSAs from Packets

```go
// Get vendor attribute
va, found := req.GetVendorAttribute(4874, 13) // ERX-Primary-Dns
if found {
    ip, _ := packet.DecodeIPAddr(va.Value)
    fmt.Printf("Primary DNS: %s\n", ip)
}

// Get all vendor attributes of a type
vas := req.GetVendorAttributes(4874, 1) // All ERX-Service-Activate
for _, va := range vas {
    fmt.Printf("Service: %s (Tag: %d)\n", string(va.GetValue()), va.Tag)
}
```

## Built-in Dictionaries

The library provides pre-defined dictionaries for common RADIUS implementations:

### Standard RFC Dictionaries

```go
import "github.com/vitalvas/goradius/pkg/dictionaries"

// Standard RFC attributes (RFC 2865, 2866, etc.)
dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)
```

### Vendor Dictionaries

```go
// Juniper ERX
dict.AddVendor(dictionaries.ERXVendorDefinition)

// Ascend
dict.AddVendor(dictionaries.AscendVendorDefinition)
```

## Complete Example

```go
package main

import (
    "fmt"
    "github.com/vitalvas/goradius/pkg/dictionary"
    "github.com/vitalvas/goradius/pkg/dictionaries"
    "github.com/vitalvas/goradius/pkg/packet"
)

func main() {
    // Create dictionary with standard attributes
    dict := dictionary.New()
    dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)
    dict.AddVendor(dictionaries.ERXVendorDefinition)

    // Create packet with dictionary
    req := packet.NewWithDictionary(packet.CodeAccessRequest, 1, dict)

    // Add attributes by name
    req.AddAttributeByName("User-Name", "john.doe")
    req.AddAttributeByName("Framed-IP-Address", "192.0.2.11")
    req.AddAttributeByName("ERX-Primary-Dns", "8.8.8.8")
    req.AddAttributeByName("ERX-Service-Activate:1", "ipoe-parking")

    // Lookup attribute information
    attr, exists := dict.LookupStandardByName("User-Name")
    if exists {
        fmt.Printf("Attribute: %s (ID: %d, Type: %s)\n",
            attr.Name, attr.ID, attr.DataType)
    }

    // Get vendor information
    vendor, exists := dict.LookupVendorByID(4874)
    if exists {
        fmt.Printf("Vendor: %s\n", vendor.Name)
    }
}
```

## Best Practices

### Dictionary Usage

1. **Create Once**: Create dictionary instances once and reuse them
2. **Use Built-in Dictionaries**: Leverage provided RFC and vendor dictionaries
3. **Efficient Lookups**: Dictionary uses map-based lookups for O(1) performance
4. **Tagged Attributes**: Use colon notation for tagged attributes (e.g., "ERX-Service-Activate:1")

### Performance

The Dictionary implementation provides:
- O(1) lookup time for attributes by ID or name
- Efficient vendor attribute lookups using composite keys
- Memory-efficient storage with shared attribute definitions

### Security

1. **Encryption Support**: Dictionary handles attribute encryption automatically when secret is provided
2. **Type Safety**: Data type validation during encoding/decoding
3. **Enumerated Values**: Support for named enumeration values for better validation
