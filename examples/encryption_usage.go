package main

import (
	"fmt"

	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
)

func main() {
	// Example showing how to use encryption flags with RADIUS attributes

	// Create a standard dictionary that includes encryption flags
	dict := dictionaries.NewStandardDictionary()

	fmt.Println("=== RADIUS Attribute Encryption Examples ===")

	// Example 1: User-Password attribute (encrypt=1, RFC2865 method)
	fmt.Println("1. User-Password Attribute:")
	userPasswordAttr, exists := dict.GetAttribute(2)
	if exists {
		fmt.Printf("   Name: %s\n", userPasswordAttr.Name)
		fmt.Printf("   Type: %d\n", userPasswordAttr.ID)
		fmt.Printf("   Data Type: %s\n", userPasswordAttr.DataType)
		fmt.Printf("   Is Encrypted: %t\n", userPasswordAttr.IsEncrypted())
		fmt.Printf("   Encryption Type: %s\n", userPasswordAttr.GetEncryptionType())
		fmt.Printf("   FreeRADIUS Format: encrypt=%s\n", userPasswordAttr.GetEncryptionType().ToNumeric())
	}
	fmt.Println()

	// Example 2: Tunnel-Password attribute (encrypt=2, RFC2868 method)
	fmt.Println("2. Tunnel-Password Attribute:")
	tunnelPasswordAttr, exists := dict.GetAttribute(69)
	if exists {
		fmt.Printf("   Name: %s\n", tunnelPasswordAttr.Name)
		fmt.Printf("   Type: %d\n", tunnelPasswordAttr.ID)
		fmt.Printf("   Data Type: %s\n", tunnelPasswordAttr.DataType)
		fmt.Printf("   Is Encrypted: %t\n", tunnelPasswordAttr.IsEncrypted())
		fmt.Printf("   Is Tagged: %t\n", tunnelPasswordAttr.IsTagged())
		fmt.Printf("   Encryption Type: %s\n", tunnelPasswordAttr.GetEncryptionType())
		fmt.Printf("   FreeRADIUS Format: encrypt=%s\n", tunnelPasswordAttr.GetEncryptionType().ToNumeric())
	}
	fmt.Println()

	// Example 3: Regular attribute without encryption
	fmt.Println("3. User-Name Attribute (no encryption):")
	userNameAttr, exists := dict.GetAttribute(1)
	if exists {
		fmt.Printf("   Name: %s\n", userNameAttr.Name)
		fmt.Printf("   Type: %d\n", userNameAttr.ID)
		fmt.Printf("   Data Type: %s\n", userNameAttr.DataType)
		fmt.Printf("   Is Encrypted: %t\n", userNameAttr.IsEncrypted())
		fmt.Printf("   Encryption Type: %s\n", userNameAttr.GetEncryptionType())
	}
	fmt.Println()

	// Example 4: Creating a custom attribute with encryption
	fmt.Println("4. Creating Custom Encrypted Attribute:")
	customDict := dictionary.NewDictionary()

	// Add a custom attribute with Ascend-Secret encryption (encrypt=3)
	customAttr := &dictionary.AttributeDefinition{
		Name:       "Custom-Secret",
		ID:         200,
		DataType:   dictionary.DataTypeOctets,
		Encryption: dictionary.EncryptionAscendSecret,
	}

	err := customDict.AddAttribute(customAttr)
	if err != nil {
		fmt.Printf("   Error adding custom attribute: %v\n", err)
	} else {
		fmt.Printf("   Name: %s\n", customAttr.Name)
		fmt.Printf("   Type: %d\n", customAttr.ID)
		fmt.Printf("   Data Type: %s\n", customAttr.DataType)
		fmt.Printf("   Is Encrypted: %t\n", customAttr.IsEncrypted())
		fmt.Printf("   Encryption Type: %s\n", customAttr.GetEncryptionType())
		fmt.Printf("   FreeRADIUS Format: encrypt=%s\n", customAttr.GetEncryptionType().ToNumeric())
	}
	fmt.Println()

	// Example 5: Parsing encryption types from FreeRADIUS format
	fmt.Println("5. Parsing FreeRADIUS Encryption Formats:")
	freeRadiusFormats := []string{"1", "2", "3", "User-Password", "Tunnel-Password", "Ascend-Secret"}

	for _, format := range freeRadiusFormats {
		encType, err := dictionary.ParseEncryptionType(format)
		if err != nil {
			fmt.Printf("   %s -> Error: %v\n", format, err)
		} else {
			fmt.Printf("   %s -> %s (numeric: %s)\n", format, encType, encType.ToNumeric())
		}
	}
	fmt.Println()

	// Example 6: Validation - encryption now supported on all data types
	fmt.Println("6. Validation Example (encryption on integer data type):")
	integerAttr := &dictionary.AttributeDefinition{
		Name:       "Encrypted-Integer",
		ID:         201,
		DataType:   dictionary.DataTypeInteger, // Encryption now supported on all types
		Encryption: dictionary.EncryptionUserPassword,
	}

	err = customDict.AddAttribute(integerAttr)
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	} else {
		fmt.Printf("   Success: Integer attribute with encryption added\n")
		fmt.Printf("   Name: %s\n", integerAttr.Name)
		fmt.Printf("   Data Type: %s\n", integerAttr.DataType)
		fmt.Printf("   Is Encrypted: %t\n", integerAttr.IsEncrypted())
		fmt.Printf("   Encryption Type: %s\n", integerAttr.GetEncryptionType())
	}
	fmt.Println()

	// Example 7: IPv6 prefix support
	fmt.Println("7. IPv6 Prefix Data Type Example:")
	ipv6PrefixAttr := &dictionary.AttributeDefinition{
		Name:     "IPv6-Prefix",
		ID:       202,
		DataType: dictionary.DataTypeIPv6Prefix,
	}

	err = customDict.AddAttribute(ipv6PrefixAttr)
	if err != nil {
		fmt.Printf("   Error: %v\n", err)
	} else {
		fmt.Printf("   Success: IPv6 prefix attribute added\n")
		fmt.Printf("   Name: %s\n", ipv6PrefixAttr.Name)
		fmt.Printf("   Data Type: %s\n", ipv6PrefixAttr.DataType)

		// Test parsing IPv6 prefix
		prefixValue, err := ipv6PrefixAttr.ParseValue("2001:db8::/64")
		if err != nil {
			fmt.Printf("   Parse Error: %v\n", err)
		} else {
			fmt.Printf("   Parsed '2001:db8::/64': %x\n", prefixValue)
		}
	}

	fmt.Println("\n=== Summary ===")
	fmt.Println("The RADIUS dictionary system supports:")
	fmt.Println("- FreeRADIUS compatibility (encrypt=1, encrypt=2, encrypt=3)")
	fmt.Println("- String format (User-Password, Tunnel-Password, Ascend-Secret)")
	fmt.Println("- Encryption on all data types (integer, ipaddr, string, octets, etc.)")
	fmt.Println("- IPv6 prefix data type with CIDR notation parsing")
	fmt.Println("- Easy integration with existing RADIUS attribute definitions")
}
