package dictionary

import (
	"fmt"
	"sort"
	"strings"
	"unicode"
)

// ValidationLevel defines the severity level of validation issues
type ValidationLevel int

const (
	ValidationLevelInfo ValidationLevel = iota
	ValidationLevelWarning
	ValidationLevelError
	ValidationLevelCritical
)

// String returns the string representation of the validation level
func (vl ValidationLevel) String() string {
	switch vl {
	case ValidationLevelInfo:
		return "INFO"
	case ValidationLevelWarning:
		return "WARNING"
	case ValidationLevelError:
		return "ERROR"
	case ValidationLevelCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// ValidationIssue represents a validation issue
type ValidationIssue struct {
	Level      ValidationLevel
	Code       string
	Message    string
	Location   string
	Attribute  *AttributeDefinition
	Vendor     *VendorDefinition
	Suggestion string
	Reference  string
}

// ValidationResult contains the results of dictionary validation
type ValidationResult struct {
	Issues      []ValidationIssue
	Summary     ValidationSummary
	IsValid     bool
	Dictionary  *Dictionary
	ValidatedAt string
}

// ValidationSummary provides a summary of validation results
type ValidationSummary struct {
	TotalIssues    int
	InfoCount      int
	WarningCount   int
	ErrorCount     int
	CriticalCount  int
	AttributeCount int
	VendorCount    int
	VSACount       int
}

// ValidationOptions configures validation behavior
type ValidationOptions struct {
	CheckNaming           bool
	CheckDuplicates       bool
	CheckTypes            bool
	CheckVendors          bool
	CheckReferences       bool
	CheckCompliance       bool
	CheckPerformance      bool
	StrictMode            bool
	IgnoreVendors         []uint32
	IgnoreAttributes      []string
	MaxNameLength         int
	AllowCustomTypes      bool
	CheckArrayConstraints bool
}

// DefaultValidationOptions returns default validation options
func DefaultValidationOptions() *ValidationOptions {
	return &ValidationOptions{
		CheckNaming:           true,
		CheckDuplicates:       true,
		CheckTypes:            true,
		CheckVendors:          true,
		CheckReferences:       true,
		CheckCompliance:       true,
		CheckPerformance:      false,
		StrictMode:            false,
		MaxNameLength:         64,
		AllowCustomTypes:      true,
		CheckArrayConstraints: true,
	}
}

// Validator provides dictionary validation functionality
type Validator struct {
	options *ValidationOptions
	issues  []ValidationIssue
}

// NewValidator creates a new dictionary validator
func NewValidator(options *ValidationOptions) *Validator {
	if options == nil {
		options = DefaultValidationOptions()
	}

	return &Validator{
		options: options,
		issues:  make([]ValidationIssue, 0),
	}
}

// Validate validates a dictionary and returns results
func (v *Validator) Validate(dict *Dictionary) *ValidationResult {
	v.issues = make([]ValidationIssue, 0)

	if dict == nil {
		v.addIssue(ValidationLevelCritical, "DICT_NULL", "Dictionary is nil", "", nil, nil, "Provide a valid dictionary", "")
		return v.buildResult(dict)
	}

	// Validate basic structure
	v.validateBasicStructure(dict)

	// Validate vendors
	if v.options.CheckVendors {
		v.validateVendors(dict)
	}

	// Validate attributes
	v.validateAttributes(dict)

	// Validate VSAs
	v.validateVSAs(dict)

	// Check for duplicates
	if v.options.CheckDuplicates {
		v.checkDuplicates(dict)
	}

	// Check references
	if v.options.CheckReferences {
		v.checkReferences(dict)
	}

	// Check compliance
	if v.options.CheckCompliance {
		v.checkCompliance(dict)
	}

	// Check performance
	if v.options.CheckPerformance {
		v.checkPerformance(dict)
	}

	return v.buildResult(dict)
}

// validateBasicStructure validates the basic dictionary structure
func (v *Validator) validateBasicStructure(dict *Dictionary) {
	if len(dict.Attributes) == 0 && len(dict.VSAs) == 0 {
		v.addIssue(ValidationLevelWarning, "DICT_EMPTY", "Dictionary contains no attributes", "", nil, nil, "Add attributes to the dictionary", "")
	}
}

// validateVendors validates vendor definitions
func (v *Validator) validateVendors(dict *Dictionary) {
	for vendorID, vendor := range dict.Vendors {
		location := fmt.Sprintf("vendors[%d]", vendorID)

		if vendor == nil {
			v.addIssue(ValidationLevelError, "VENDOR_NULL", "Vendor definition is nil", location, nil, vendor, "", "")
			continue
		}

		if vendor.ID != vendorID {
			v.addIssue(ValidationLevelError, "VENDOR_ID_MISMATCH", fmt.Sprintf("Vendor ID mismatch: map key %d != vendor.ID %d", vendorID, vendor.ID), location, nil, vendor, "Fix vendor ID", "")
		}

		if vendor.ID == 0 {
			v.addIssue(ValidationLevelError, "VENDOR_ZERO_ID", "Vendor ID cannot be zero", location, nil, vendor, "Use a valid vendor ID", "")
		}

		if vendor.Name == "" {
			v.addIssue(ValidationLevelError, "VENDOR_NO_NAME", "Vendor has no name", location, nil, vendor, "Set a vendor name", "")
		}

		if v.options.CheckNaming && vendor.Name != "" {
			if !v.isValidVendorName(vendor.Name) {
				v.addIssue(ValidationLevelError, "VENDOR_INVALID_NAME", "Vendor name contains invalid characters", location, nil, vendor, "Use standard vendor naming conventions", "")
			}

			if len(vendor.Name) > v.options.MaxNameLength {
				v.addIssue(ValidationLevelWarning, "VENDOR_NAME_TOO_LONG", fmt.Sprintf("Vendor name exceeds maximum length (%d)", v.options.MaxNameLength), location, nil, vendor, "Shorten vendor name", "")
			}
		}

		// Check for well-known vendor IDs
		v.checkWellKnownVendor(vendor, location)
	}
}

// validateAttributes validates standard attributes
func (v *Validator) validateAttributes(dict *Dictionary) {
	for attrType, attr := range dict.Attributes {
		location := fmt.Sprintf("attributes[%d]", attrType)

		if attr == nil {
			v.addIssue(ValidationLevelError, "ATTR_NULL", "Attribute definition is nil", location, attr, nil, "", "")
			continue
		}

		v.validateAttribute(attr, location)

		if attr.ID != attrType {
			v.addIssue(ValidationLevelError, "ATTR_TYPE_MISMATCH", fmt.Sprintf("Attribute type mismatch: map key %d != attr.ID %d", attrType, attr.ID), location, attr, nil, "Fix attribute type", "")
		}

		if attr.VendorID != 0 {
			v.addIssue(ValidationLevelError, "ATTR_VENDOR_ID_SET", "Standard attribute has vendor ID set", location, attr, nil, "Remove vendor ID or move to VSA", "")
		}
	}
}

// validateVSAs validates vendor-specific attributes
func (v *Validator) validateVSAs(dict *Dictionary) {
	for vendorID, vendorAttrs := range dict.VSAs {
		if _, exists := dict.Vendors[vendorID]; !exists {
			v.addIssue(ValidationLevelError, "VSA_UNKNOWN_VENDOR", fmt.Sprintf("VSA references unknown vendor ID: %d", vendorID), fmt.Sprintf("vsas[%d]", vendorID), nil, nil, "Add vendor definition or remove VSA", "")
		}

		for attrType, attr := range vendorAttrs {
			location := fmt.Sprintf("vsas[%d][%d]", vendorID, attrType)

			if attr == nil {
				v.addIssue(ValidationLevelError, "VSA_NULL", "VSA definition is nil", location, attr, nil, "", "")
				continue
			}

			v.validateAttribute(attr, location)

			if attr.ID != attrType {
				v.addIssue(ValidationLevelError, "VSA_TYPE_MISMATCH", fmt.Sprintf("VSA type mismatch: map key %d != attr.ID %d", attrType, attr.ID), location, attr, nil, "Fix VSA type", "")
			}

			if attr.VendorID != vendorID {
				v.addIssue(ValidationLevelError, "VSA_VENDOR_ID_MISMATCH", fmt.Sprintf("VSA vendor ID mismatch: map key %d != attr.VendorID %d", vendorID, attr.VendorID), location, attr, nil, "Fix vendor ID", "")
			}
		}
	}
}

// validateAttribute validates a single attribute
func (v *Validator) validateAttribute(attr *AttributeDefinition, location string) {
	if attr.Name == "" {
		v.addIssue(ValidationLevelError, "ATTR_NO_NAME", "Attribute has no name", location, attr, nil, "Set attribute name", "")
		return
	}

	// Check naming conventions
	if v.options.CheckNaming {
		if !v.isValidAttributeName(attr.Name) {
			v.addIssue(ValidationLevelError, "ATTR_INVALID_NAME", "Attribute name contains invalid characters", location, attr, nil, "Use standard RADIUS attribute naming conventions", "")
		}

		if len(attr.Name) > v.options.MaxNameLength {
			v.addIssue(ValidationLevelWarning, "ATTR_NAME_TOO_LONG", fmt.Sprintf("Attribute name exceeds maximum length (%d)", v.options.MaxNameLength), location, attr, nil, "Shorten attribute name", "")
		}
	}

	// Check data type
	if v.options.CheckTypes {
		if !v.isValidDataType(attr.DataType) {
			v.addIssue(ValidationLevelError, "ATTR_INVALID_TYPE", fmt.Sprintf("Invalid data type: %s", attr.DataType), location, attr, nil, "Use a valid data type", "")
		}

		// Check type-specific constraints
		v.validateTypeConstraints(attr, location)
	}

	// Check array constraints
	if v.options.CheckArrayConstraints && attr.Array {
		v.validateArrayConstraints(attr, location)
	}

	// Check values (enumerations)
	if len(attr.Values) > 0 {
		v.validateEnumerations(attr, location)
	}

}

// validateTypeConstraints validates type-specific constraints
func (v *Validator) validateTypeConstraints(attr *AttributeDefinition, location string) {
	switch attr.DataType {
	case DataTypeString, DataTypeOctets:
		if attr.Length > 253 {
			v.addIssue(ValidationLevelError, "ATTR_LENGTH_TOO_LONG", fmt.Sprintf("%s attribute length cannot exceed 253 bytes", attr.DataType), location, attr, nil, "Reduce length or use variable length", "")
		}

	case DataTypeInteger, DataTypeUint32, DataTypeDate, DataTypeIPAddr:
		if attr.Length > 0 && attr.Length != 4 {
			v.addIssue(ValidationLevelError, "ATTR_INVALID_LENGTH", fmt.Sprintf("%s attributes must be exactly 4 bytes", attr.DataType), location, attr, nil, "Remove length specification or set to 4", "")
		}

	case DataTypeUint64:
		if attr.Length > 0 && attr.Length != 8 {
			v.addIssue(ValidationLevelError, "ATTR_INVALID_LENGTH", "uint64 attributes must be exactly 8 bytes", location, attr, nil, "Remove length specification or set to 8", "")
		}

	case DataTypeIPv6Addr:
		if attr.Length > 0 && attr.Length != 16 {
			v.addIssue(ValidationLevelError, "ATTR_INVALID_LENGTH", "ipv6addr attributes must be exactly 16 bytes", location, attr, nil, "Remove length specification or set to 16", "")
		}
	}
}

// validateArrayConstraints validates array-specific constraints
func (v *Validator) validateArrayConstraints(attr *AttributeDefinition, location string) {
	if attr.Array {
		// Check if data type is suitable for arrays
		switch attr.DataType {
		case DataTypeString, DataTypeOctets, DataTypeInteger, DataTypeUint32, DataTypeUint64, DataTypeIPAddr, DataTypeIPv6Addr:
			// These are fine for arrays
		default:
			v.addIssue(ValidationLevelWarning, "ATTR_ARRAY_TYPE_UNUSUAL", fmt.Sprintf("Data type %s is unusual for array attributes", attr.DataType), location, attr, nil, "Consider if array is appropriate", "")
		}

		// Arrays with fixed length can be problematic
		if attr.Length > 0 && attr.Length > 100 {
			v.addIssue(ValidationLevelWarning, "ATTR_ARRAY_LARGE_FIXED", "Array with large fixed length may cause issues", location, attr, nil, "Consider using variable length", "")
		}
	}
}

// validateEnumerations validates enumeration values
func (v *Validator) validateEnumerations(attr *AttributeDefinition, location string) {
	if len(attr.Values) == 0 {
		return
	}

	// Check for duplicate values
	seenValues := make(map[uint32]string)
	for name, value := range attr.Values {
		if existing, exists := seenValues[value]; exists {
			v.addIssue(ValidationLevelError, "ATTR_ENUM_DUPLICATE", fmt.Sprintf("Duplicate enumeration value %d for names '%s' and '%s'", value, existing, name), location, attr, nil, "Use unique values", "")
		}
		seenValues[value] = name

		// Check name format
		if v.options.CheckNaming && !v.isValidEnumName(name) {
			v.addIssue(ValidationLevelWarning, "ATTR_ENUM_INVALID_NAME", fmt.Sprintf("Enumeration name '%s' doesn't follow conventions", name), location, attr, nil, "Use standard enumeration naming", "")
		}
	}

	// Check if enumerations are appropriate for the data type
	switch attr.DataType {
	case DataTypeString:
		v.addIssue(ValidationLevelWarning, "ATTR_ENUM_STRING_TYPE", "Enumerations on string attributes are unusual", location, attr, nil, "Consider using integer type", "")
	case DataTypeOctets:
		v.addIssue(ValidationLevelWarning, "ATTR_ENUM_OCTETS_TYPE", "Enumerations on octets attributes are unusual", location, attr, nil, "Consider using integer type", "")
	}
}

// checkDuplicates checks for duplicate attribute names and types
func (v *Validator) checkDuplicates(dict *Dictionary) {
	// Check for duplicate names across all attributes
	nameMap := make(map[string][]string)

	// Standard attributes
	for _, attr := range dict.Attributes {
		if attr.Name != "" {
			key := strings.ToLower(attr.Name)
			nameMap[key] = append(nameMap[key], fmt.Sprintf("attributes[%d]", attr.ID))
		}
	}

	// VSAs
	for vendorID, vendorAttrs := range dict.VSAs {
		for _, attr := range vendorAttrs {
			if attr.Name != "" {
				key := strings.ToLower(attr.Name)
				nameMap[key] = append(nameMap[key], fmt.Sprintf("vsas[%d][%d]", vendorID, attr.ID))
			}
		}
	}

	// Report duplicates
	for name, locations := range nameMap {
		if len(locations) > 1 {
			v.addIssue(ValidationLevelError, "ATTR_DUPLICATE_NAME", fmt.Sprintf("Duplicate attribute name '%s' found at: %s", name, strings.Join(locations, ", ")), "", nil, nil, "Use unique names", "")
		}
	}
}

// checkReferences checks for reference integrity
func (v *Validator) checkReferences(dict *Dictionary) {
	// Check VSA vendor references
	for vendorID := range dict.VSAs {
		if _, exists := dict.Vendors[vendorID]; !exists {
			v.addIssue(ValidationLevelError, "VSA_ORPHANED", fmt.Sprintf("VSA references non-existent vendor ID: %d", vendorID), fmt.Sprintf("vsas[%d]", vendorID), nil, nil, "Add vendor definition", "")
		}
	}

	// Check for unused vendors
	for vendorID, vendor := range dict.Vendors {
		if _, exists := dict.VSAs[vendorID]; !exists {
			v.addIssue(ValidationLevelInfo, "VENDOR_UNUSED", fmt.Sprintf("Vendor '%s' has no VSAs", vendor.Name), fmt.Sprintf("vendors[%d]", vendorID), nil, vendor, "Add VSAs or remove vendor", "")
		}
	}
}

// checkCompliance checks for RFC compliance
func (v *Validator) checkCompliance(dict *Dictionary) {
	// Check for reserved attribute types
	reservedTypes := map[uint8]string{
		0:   "Reserved",
		255: "Reserved",
	}

	for attrType, description := range reservedTypes {
		if _, exists := dict.Attributes[attrType]; exists {
			v.addIssue(ValidationLevelError, "ATTR_RESERVED_TYPE", fmt.Sprintf("Attribute type %d is reserved: %s", attrType, description), fmt.Sprintf("attributes[%d]", attrType), dict.Attributes[attrType], nil, "Use a different attribute type", "RFC 2865")
		}
	}

	// Check for standard attribute compliance
	v.checkStandardAttributes(dict)
}

// checkStandardAttributes checks for standard RADIUS attributes
func (v *Validator) checkStandardAttributes(dict *Dictionary) {
	standardAttrs := map[uint8]string{
		1:  "User-Name",
		2:  "User-Password",
		4:  "NAS-IP-Address",
		5:  "NAS-Port",
		6:  "Service-Type",
		8:  "Framed-IP-Address",
		80: "Message-Authenticator",
	}

	for attrType, expectedName := range standardAttrs {
		if attr, exists := dict.Attributes[attrType]; exists {
			if attr.Name != expectedName {
				v.addIssue(ValidationLevelWarning, "ATTR_NONSTANDARD_NAME", fmt.Sprintf("Standard attribute %d should be named '%s', found '%s'", attrType, expectedName, attr.Name), fmt.Sprintf("attributes[%d]", attrType), attr, nil, "Use standard name", "RFC 2865")
			}
		}
	}
}

// checkPerformance checks for performance-related issues
func (v *Validator) checkPerformance(dict *Dictionary) {
	// Check for very long attribute names
	for _, attr := range dict.Attributes {
		if len(attr.Name) > 50 {
			v.addIssue(ValidationLevelInfo, "ATTR_NAME_LONG", "Very long attribute name may impact performance", "", attr, nil, "Consider shorter name", "")
		}
	}

	// Check for large dictionaries
	totalAttrs := len(dict.Attributes)
	for _, vendorAttrs := range dict.VSAs {
		totalAttrs += len(vendorAttrs)
	}

	if totalAttrs > 1000 {
		v.addIssue(ValidationLevelInfo, "DICT_LARGE", fmt.Sprintf("Dictionary contains %d attributes, which may impact performance", totalAttrs), "", nil, nil, "Consider splitting large dictionaries", "")
	}
}

// checkWellKnownVendor checks for well-known vendor IDs
func (v *Validator) checkWellKnownVendor(vendor *VendorDefinition, location string) {
	wellKnownVendors := map[uint32]string{
		9:     "Cisco",
		311:   "Microsoft",
		2636:  "Juniper",
		14988: "Mikrotik",
	}

	if expectedName, exists := wellKnownVendors[vendor.ID]; exists {
		if vendor.Name != expectedName {
			v.addIssue(ValidationLevelWarning, "VENDOR_NONSTANDARD_NAME", fmt.Sprintf("Well-known vendor %d should be named '%s', found '%s'", vendor.ID, expectedName, vendor.Name), location, nil, vendor, "Use standard vendor name", "")
		}
	}
}

// Helper methods for validation

func (v *Validator) isValidName(name string) bool {
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func (v *Validator) isValidVendorName(name string) bool {
	// Vendor names should be title case and contain only letters, numbers, spaces, and hyphens
	for _, r := range name {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != ' ' && r != '-' {
			return false
		}
	}
	return true
}

func (v *Validator) isValidAttributeName(name string) bool {
	// Attribute names should follow RADIUS conventions: Title-Case-With-Hyphens
	if name == "" {
		return false
	}

	parts := strings.Split(name, "-")
	for _, part := range parts {
		if len(part) == 0 {
			return false
		}

		// First character should be uppercase
		if !unicode.IsUpper(rune(part[0])) {
			return false
		}

		// Rest should be lowercase letters or numbers
		for _, r := range part[1:] {
			if !unicode.IsLower(r) && !unicode.IsDigit(r) {
				return false
			}
		}
	}

	return true
}

func (v *Validator) isValidEnumName(name string) bool {
	// Enum names should be Title-Case-With-Hyphens
	return v.isValidAttributeName(name)
}

func (v *Validator) isValidDataType(dataType DataType) bool {
	switch dataType {
	case DataTypeString, DataTypeOctets, DataTypeInteger, DataTypeUint32, DataTypeUint64, DataTypeDate, DataTypeIPAddr, DataTypeIPv6Addr:
		return true
	default:
		return v.options.AllowCustomTypes
	}
}

func (v *Validator) addIssue(level ValidationLevel, code, message, location string, attr *AttributeDefinition, vendor *VendorDefinition, suggestion, reference string) {
	issue := ValidationIssue{
		Level:      level,
		Code:       code,
		Message:    message,
		Location:   location,
		Attribute:  attr,
		Vendor:     vendor,
		Suggestion: suggestion,
		Reference:  reference,
	}

	v.issues = append(v.issues, issue)
}

func (v *Validator) buildResult(dict *Dictionary) *ValidationResult {
	summary := v.buildSummary(dict)

	// Sort issues by level (critical first)
	sort.Slice(v.issues, func(i, j int) bool {
		return v.issues[i].Level > v.issues[j].Level
	})

	isValid := summary.CriticalCount == 0 && summary.ErrorCount == 0
	if v.options.StrictMode {
		isValid = isValid && summary.WarningCount == 0
	}

	return &ValidationResult{
		Issues:      v.issues,
		Summary:     summary,
		IsValid:     isValid,
		Dictionary:  dict,
		ValidatedAt: fmt.Sprintf("%d issues found", len(v.issues)),
	}
}

func (v *Validator) buildSummary(dict *Dictionary) ValidationSummary {
	summary := ValidationSummary{
		TotalIssues: len(v.issues),
	}

	for _, issue := range v.issues {
		switch issue.Level {
		case ValidationLevelInfo:
			summary.InfoCount++
		case ValidationLevelWarning:
			summary.WarningCount++
		case ValidationLevelError:
			summary.ErrorCount++
		case ValidationLevelCritical:
			summary.CriticalCount++
		}
	}

	if dict != nil {
		summary.AttributeCount = len(dict.Attributes)
		summary.VendorCount = len(dict.Vendors)

		for _, vendorAttrs := range dict.VSAs {
			summary.VSACount += len(vendorAttrs)
		}
	}

	return summary
}

// Linter provides dictionary linting functionality
type Linter struct {
	validator *Validator
}

// NewLinter creates a new dictionary linter
func NewLinter(options *ValidationOptions) *Linter {
	return &Linter{
		validator: NewValidator(options),
	}
}

// Lint performs comprehensive linting of a dictionary
func (l *Linter) Lint(dict *Dictionary) *ValidationResult {
	return l.validator.Validate(dict)
}

// LintAndFix performs linting and suggests fixes
func (l *Linter) LintAndFix(dict *Dictionary) (*ValidationResult, []string) {
	result := l.Lint(dict)
	fixes := l.generateFixes(result)
	return result, fixes
}

// generateFixes generates suggested fixes for validation issues
func (l *Linter) generateFixes(result *ValidationResult) []string {
	fixes := make([]string, 0)

	for _, issue := range result.Issues {
		if issue.Suggestion != "" {
			fix := fmt.Sprintf("%s: %s", issue.Code, issue.Suggestion)
			fixes = append(fixes, fix)
		}
	}

	return fixes
}

// QuickLint performs a quick validation with minimal checks
func QuickLint(dict *Dictionary) *ValidationResult {
	options := &ValidationOptions{
		CheckNaming:      false,
		CheckDuplicates:  true,
		CheckTypes:       true,
		CheckVendors:     true,
		CheckReferences:  true,
		CheckCompliance:  false,
		CheckPerformance: false,
	}

	validator := NewValidator(options)
	return validator.Validate(dict)
}

// StrictLint performs strict validation with all checks enabled
func StrictLint(dict *Dictionary) *ValidationResult {
	options := &ValidationOptions{
		CheckNaming:           true,
		CheckDuplicates:       true,
		CheckTypes:            true,
		CheckVendors:          true,
		CheckReferences:       true,
		CheckCompliance:       true,
		CheckPerformance:      true,
		StrictMode:            true,
		MaxNameLength:         50,
		AllowCustomTypes:      false,
		CheckArrayConstraints: true,
	}

	validator := NewValidator(options)
	return validator.Validate(dict)
}
