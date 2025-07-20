package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidationLevel_String(t *testing.T) {
	tests := []struct {
		level    ValidationLevel
		expected string
	}{
		{ValidationLevelError, "ERROR"},
		{ValidationLevelWarning, "WARNING"},
		{ValidationLevelInfo, "INFO"},
		{ValidationLevelCritical, "CRITICAL"},
		{ValidationLevel(99), "UNKNOWN"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			assert.Equal(t, test.expected, test.level.String())
		})
	}
}

func TestDefaultValidationOptions(t *testing.T) {
	opts := DefaultValidationOptions()

	assert.NotNil(t, opts)
	assert.True(t, opts.CheckDuplicates)
	assert.True(t, opts.CheckReferences)
}

func TestNewValidator(t *testing.T) {
	opts := DefaultValidationOptions()
	validator := NewValidator(opts)

	assert.NotNil(t, validator)
}

func TestValidationIssue_Methods(t *testing.T) {
	issue := ValidationIssue{
		Level:    ValidationLevelError,
		Code:     "TEST001",
		Message:  "Test error message",
		Location: "test.field",
	}

	// Test basic fields
	assert.Equal(t, ValidationLevelError, issue.Level)
	assert.Equal(t, "TEST001", issue.Code)
	assert.Equal(t, "Test error message", issue.Message)
	assert.Equal(t, "test.field", issue.Location)
}

func TestValidationResult_Basic(t *testing.T) {
	result := &ValidationResult{
		Issues: []ValidationIssue{
			{
				Level:   ValidationLevelError,
				Message: "Test error",
			},
			{
				Level:   ValidationLevelWarning,
				Message: "Test warning",
			},
		},
		IsValid: false,
	}

	assert.NotNil(t, result)
	assert.Len(t, result.Issues, 2)
	assert.False(t, result.IsValid)
}

func TestNewLinter(t *testing.T) {
	opts := DefaultValidationOptions()
	linter := NewLinter(opts)
	assert.NotNil(t, linter)
}

func TestQuickLint(t *testing.T) {
	dict := &Dictionary{
		Vendors:    make(map[uint32]*VendorDefinition),
		Attributes: make(map[uint8]*AttributeDefinition),
		VSAs:       make(map[uint32]map[uint8]*AttributeDefinition),
	}

	result := QuickLint(dict)
	assert.NotNil(t, result)
}

func TestStrictLint(t *testing.T) {
	dict := &Dictionary{
		Vendors:    make(map[uint32]*VendorDefinition),
		Attributes: make(map[uint8]*AttributeDefinition),
		VSAs:       make(map[uint32]map[uint8]*AttributeDefinition),
	}

	result := StrictLint(dict)
	assert.NotNil(t, result)
}
