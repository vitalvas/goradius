# RADIUS Dictionary Usage

This guide covers how to work with RADIUS
dictionaries for attribute definitions, validation,
and vendor-specific attributes.

## Dictionary Overview

The dictionary system provides:

- Fast attribute lookups by ID and name
- Vendor-specific attribute (VSA) support
- In-code dictionary definitions
- Type-safe attribute handling with data type support

## Dictionary Structure

The Dictionary uses efficient map-based lookups for
both standard and vendor-specific attributes.

### Creating a Dictionary

```go
import "github.com/vitalvas/goradius"

// Create a new dictionary
dict := goradius.NewDictionary()

// Add standard RFC attributes
dict.AddStandardAttributes(
    goradius.StandardRFCAttributes,
)

// Add vendor definitions
dict.AddVendor(goradius.ERXVendorDefinition)
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
    Encryption  EncryptionType    // Encryption
    HasTag      bool              // Tagging
    Array       bool              // Multi-value
    Values      map[string]uint32 // Enum values
    Description string            // Description
}
```

Attribute names must be lowercase only.

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
attr, exists := dict.LookupStandardByID(1)
if exists {
    fmt.Printf(
        "Attribute: %s, Data Type: %s\n",
        attr.Name, attr.DataType,
    )
}

// Lookup by name
attr, exists = dict.LookupStandardByName(
    "user-name",
)
if exists {
    fmt.Printf(
        "Attribute ID: %d, Data Type: %s\n",
        attr.ID, attr.DataType,
    )
}
```

### Lookup Vendor Attributes

```go
// Lookup vendor by ID
vendor, exists := dict.LookupVendorByID(4874)
if exists {
    fmt.Printf("Vendor: %s\n", vendor.Name)
}

// Lookup vendor attribute by IDs
attr, exists := dict.LookupVendorAttributeByID(
    4874, 1,
)
if exists {
    fmt.Printf(
        "Vendor Attribute: %s\n", attr.Name,
    )
}

// Lookup any attribute by name
// (works for both standard and vendor attributes)
attr, exists = dict.LookupByAttributeName(
    "erx-service-activate",
)
if exists {
    fmt.Printf("Attribute ID: %d\n", attr.ID)
}

// Find vendor ID for a vendor attribute
vendorID, exists := dict.LookupVendorIDByAttributeName(
    "erx-service-activate",
)
if exists {
    fmt.Printf("Vendor ID: %d\n", vendorID)
}
```

### Get All Vendors

```go
vendors := dict.GetAllVendors()
for _, vendor := range vendors {
    fmt.Printf(
        "Vendor: %s (ID: %d)\n",
        vendor.Name, vendor.ID,
    )
    for _, attr := range vendor.Attributes {
        fmt.Printf(
            "  - %s (ID: %d, Type: %s)\n",
            attr.Name, attr.ID, attr.DataType,
        )
    }
}
```

## Using Dictionaries with Packets

### Adding Attributes by Name

```go
import "github.com/vitalvas/goradius"

// Create packet with dictionary
req := goradius.NewWithDictionary(
    goradius.CodeAccessRequest, 1, dict,
)

// Add attribute by name
req.AddAttributeByName("user-name", "john.doe")
req.AddAttributeByName(
    "framed-ip-address", "192.0.2.11",
)

// Add vendor attribute by name
req.AddAttributeByName(
    "erx-primary-dns", "8.8.8.8",
)
```

### Adding Attributes with Encryption

```go
secret := []byte("testing123")
authenticator := req.Authenticator

// Add encrypted password
req.AddAttributeByNameWithSecret(
    "user-password", "secret123",
    secret, authenticator,
)

// The library handles encryption based on
// the attribute definition
```

### Working with Enumerated Values

```go
// If an attribute has enumerated values in
// the dictionary, you can use the string name
// instead of numeric value
attr := &goradius.AttributeDefinition{
    ID:       6,
    Name:     "service-type",
    DataType: goradius.DataTypeInteger,
    Values: map[string]uint32{
        "Login":  1,
        "Framed": 2,
    },
}

// Add to dictionary
dict.AddStandardAttributes(
    []*goradius.AttributeDefinition{attr},
)

// Use enumerated value by name
req.AddAttributeByName(
    "service-type", "Login",
) // Converts to 1
```

## Vendor-Specific Attributes

### Defining Vendor Attributes

```go
// Define vendor with attributes
vendor := &goradius.VendorDefinition{
    ID:          4874,
    Name:        "erx",
    Description: "Juniper ERX",
    Attributes: []*goradius.AttributeDefinition{
        {
            ID:       1,
            Name:     "erx-service-activate",
            DataType: goradius.DataTypeString,
            HasTag:   true,
        },
        {
            ID:       4,
            Name:     "erx-primary-dns",
            DataType: goradius.DataTypeIPAddr,
        },
    },
}

// Add vendor to dictionary
dict.AddVendor(vendor)
```

### Using VSAs in Packets

The recommended approach is to use the dictionary API
which handles VSA encoding automatically:

```go
// Add vendor attribute by name
req.AddAttributeByName(
    "erx-primary-dns", "8.8.8.8",
)
req.AddAttributeByName(
    "erx-secondary-dns", "8.8.4.4",
)

// Add tagged vendor attribute using colon notation
req.AddAttributeByName(
    "erx-service-activate:1", "ipoe-parking",
)
req.AddAttributeByName(
    "erx-service-activate:3",
    "svc-ipoe-policer(52428800, 52428800)",
)

// The library automatically:
// - Looks up the vendor ID from the dictionary
// - Encodes the VSA with the proper structure
// - Handles tagging if the attribute supports it
```

### Retrieving VSAs from Packets

Use the high-level dictionary API for retrieving
vendor attributes:

```go
// Get vendor attribute by name
dnsValues := req.GetAttribute("erx-primary-dns")
if len(dnsValues) > 0 {
    fmt.Printf(
        "Primary DNS: %s\n",
        dnsValues[0].String(),
    )
}

// Get all vendor attributes (including tagged ones)
services := req.GetAttribute(
    "erx-service-activate",
)
for _, svc := range services {
    if svc.Tag > 0 {
        fmt.Printf(
            "Service (Tag %d): %s\n",
            svc.Tag, svc.String(),
        )
    }
}
```

## Built-in Dictionaries

The library provides pre-defined dictionaries for
common RADIUS implementations.

### Using the Default Dictionary

The simplest way to get started is using the default
dictionary with all standard attributes and common
vendors:

```go
import "github.com/vitalvas/goradius"

// Create dictionary with standard RFC attributes
// and common vendors
dict, err := goradius.NewDefault()
if err != nil {
    log.Fatal(err)
}

// Ready to use!
pkt := goradius.NewWithDictionary(
    goradius.CodeAccessRequest, 1, dict,
)
```

### Building Custom Dictionaries

For more control, you can build a dictionary
manually:

```go
import "github.com/vitalvas/goradius"

// Create empty dictionary
dict := goradius.NewDictionary()

// Add standard RFC attributes
dict.AddStandardAttributes(
    goradius.StandardRFCAttributes,
)

// Add specific vendors as needed
dict.AddVendor(goradius.ERXVendorDefinition)
dict.AddVendor(goradius.AscendVendorDefinition)
```

## Complete Example

```go
package main

import (
    "fmt"
    "log"

    "github.com/vitalvas/goradius"
)

func main() {
    // Create dictionary with all standard
    // attributes and common vendors
    dict, err := goradius.NewDefault()
    if err != nil {
        log.Fatal(err)
    }

    // Create packet with dictionary
    req := goradius.NewWithDictionary(
        goradius.CodeAccessRequest, 1, dict,
    )

    // Add attributes by name
    req.AddAttributeByName(
        "user-name", "john.doe",
    )
    req.AddAttributeByName(
        "framed-ip-address", "192.0.2.11",
    )
    req.AddAttributeByName(
        "erx-primary-dns", "8.8.8.8",
    )
    req.AddAttributeByName(
        "erx-service-activate:1", "ipoe-parking",
    )

    // Lookup attribute information
    attr, exists := dict.LookupStandardByName(
        "user-name",
    )
    if exists {
        fmt.Printf(
            "Attribute: %s (ID: %d, Type: %s)\n",
            attr.Name, attr.ID, attr.DataType,
        )
    }

    // Get vendor information
    vendor, exists := dict.LookupVendorByID(4874)
    if exists {
        fmt.Printf("Vendor: %s\n", vendor.Name)
    }
}
```
