package dictionary

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFixedLengthType(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    FixedLengthType
		expectError bool
	}{
		{
			name:  "simple string type",
			input: "string",
			expected: FixedLengthType{
				BaseType: DataTypeString,
				Length:   0,
			},
		},
		{
			name:  "fixed-length string",
			input: "string[10]",
			expected: FixedLengthType{
				BaseType: DataTypeString,
				Length:   10,
			},
		},
		{
			name:  "fixed-length octets",
			input: "octets[16]",
			expected: FixedLengthType{
				BaseType: DataTypeOctets,
				Length:   16,
			},
		},
		{
			name:  "integer type",
			input: "integer",
			expected: FixedLengthType{
				BaseType: DataTypeInteger,
				Length:   0,
			},
		},
		{
			name:  "fixed-length integer",
			input: "integer[4]",
			expected: FixedLengthType{
				BaseType: DataTypeInteger,
				Length:   4,
			},
		},
		{
			name:        "invalid base type",
			input:       "invalid",
			expectError: true,
		},
		{
			name:        "invalid length",
			input:       "string[abc]",
			expectError: true,
		},
		{
			name:        "zero length",
			input:       "string[0]",
			expectError: true,
		},
		{
			name:        "negative length",
			input:       "string[-1]",
			expectError: true,
		},
		{
			name:        "invalid format",
			input:       "string[10",
			expectError: true,
		},
		{
			name:        "string too long",
			input:       "string[300]",
			expectError: true,
		},
		{
			name:        "integer wrong length",
			input:       "integer[8]",
			expectError: true,
		},
		{
			name:        "uint64 wrong length",
			input:       "uint64[4]",
			expectError: true,
		},
		{
			name:        "ipaddr wrong length",
			input:       "ipaddr[6]",
			expectError: true,
		},
		{
			name:        "ipv6addr wrong length",
			input:       "ipv6addr[12]",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseFixedLengthType(tt.input)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFixedLengthType_String(t *testing.T) {
	tests := []struct {
		name     string
		flt      FixedLengthType
		expected string
	}{
		{
			name: "variable length string",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   0,
			},
			expected: "string",
		},
		{
			name: "fixed length string",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   10,
			},
			expected: "string[10]",
		},
		{
			name: "fixed length octets",
			flt: FixedLengthType{
				BaseType: DataTypeOctets,
				Length:   16,
			},
			expected: "octets[16]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flt.String()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFixedLengthType_GetNaturalLength(t *testing.T) {
	tests := []struct {
		name     string
		flt      FixedLengthType
		expected int
	}{
		{
			name: "string has no natural length",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   0,
			},
			expected: 0,
		},
		{
			name: "integer has natural length 4",
			flt: FixedLengthType{
				BaseType: DataTypeInteger,
				Length:   0,
			},
			expected: 4,
		},
		{
			name: "uint64 has natural length 8",
			flt: FixedLengthType{
				BaseType: DataTypeUint64,
				Length:   0,
			},
			expected: 8,
		},
		{
			name: "ipv6addr has natural length 16",
			flt: FixedLengthType{
				BaseType: DataTypeIPv6Addr,
				Length:   0,
			},
			expected: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flt.GetNaturalLength()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFixedLengthType_GetEffectiveLength(t *testing.T) {
	tests := []struct {
		name     string
		flt      FixedLengthType
		expected int
	}{
		{
			name: "specified length takes precedence",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   10,
			},
			expected: 10,
		},
		{
			name: "natural length when no specified length",
			flt: FixedLengthType{
				BaseType: DataTypeInteger,
				Length:   0,
			},
			expected: 4,
		},
		{
			name: "zero for variable length types",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   0,
			},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flt.GetEffectiveLength()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFixedLengthType_ValidateValueLength(t *testing.T) {
	tests := []struct {
		name        string
		flt         FixedLengthType
		value       []byte
		expectError bool
	}{
		{
			name: "correct length string",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   10,
			},
			value:       make([]byte, 10),
			expectError: false,
		},
		{
			name: "incorrect length string",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   10,
			},
			value:       make([]byte, 5),
			expectError: true,
		},
		{
			name: "correct natural length integer",
			flt: FixedLengthType{
				BaseType: DataTypeInteger,
				Length:   0,
			},
			value:       make([]byte, 4),
			expectError: false,
		},
		{
			name: "incorrect natural length integer",
			flt: FixedLengthType{
				BaseType: DataTypeInteger,
				Length:   0,
			},
			value:       make([]byte, 8),
			expectError: true,
		},
		{
			name: "variable length type accepts any length",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   0,
			},
			value:       make([]byte, 100),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.flt.ValidateValueLength(tt.value)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFixedLengthType_PadValue(t *testing.T) {
	tests := []struct {
		name     string
		flt      FixedLengthType
		value    []byte
		expected []byte
	}{
		{
			name: "pad string with null bytes",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   10,
			},
			value:    []byte("hello"),
			expected: []byte("hello\x00\x00\x00\x00\x00"),
		},
		{
			name: "pad octets with zero bytes",
			flt: FixedLengthType{
				BaseType: DataTypeOctets,
				Length:   8,
			},
			value:    []byte{0x01, 0x02, 0x03},
			expected: []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "no padding for exact length",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   5,
			},
			value:    []byte("hello"),
			expected: []byte("hello"),
		},
		{
			name: "no padding for variable length",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   0,
			},
			value:    []byte("hello"),
			expected: []byte("hello"),
		},
		{
			name: "no padding for non-paddable types",
			flt: FixedLengthType{
				BaseType: DataTypeInteger,
				Length:   4,
			},
			value:    []byte{0x01, 0x02},
			expected: []byte{0x01, 0x02},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flt.PadValue(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFixedLengthType_TrimValue(t *testing.T) {
	tests := []struct {
		name     string
		flt      FixedLengthType
		value    []byte
		expected []byte
	}{
		{
			name: "trim null bytes from string",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   10,
			},
			value:    []byte("hello\x00\x00\x00\x00\x00"),
			expected: []byte("hello"),
		},
		{
			name: "trim all null bytes",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   5,
			},
			value:    []byte("\x00\x00\x00\x00\x00"),
			expected: []byte{},
		},
		{
			name: "no trimming for octets",
			flt: FixedLengthType{
				BaseType: DataTypeOctets,
				Length:   8,
			},
			value:    []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00},
		},
		{
			name: "no trimming for variable length",
			flt: FixedLengthType{
				BaseType: DataTypeString,
				Length:   0,
			},
			value:    []byte("hello\x00\x00"),
			expected: []byte("hello\x00\x00"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.flt.TrimValue(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttributeDefinition_GetFixedLengthType(t *testing.T) {
	attr := &AttributeDefinition{
		Name:     "Test-Attribute",
		ID:       100,
		DataType: DataTypeString,
		Length:   10,
	}

	flt := attr.GetFixedLengthType()
	assert.Equal(t, DataTypeString, flt.BaseType)
	assert.Equal(t, 10, flt.Length)
}

func TestAttributeDefinition_GetMinimumLength(t *testing.T) {
	tests := []struct {
		name     string
		attr     *AttributeDefinition
		expected int
	}{
		{
			name: "fixed-length string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   10,
			},
			expected: 10,
		},
		{
			name: "variable-length string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   0,
			},
			expected: 0,
		},
		{
			name: "integer",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
				Length:   0,
			},
			expected: 4,
		},
		{
			name: "uint64",
			attr: &AttributeDefinition{
				DataType: DataTypeUint64,
				Length:   0,
			},
			expected: 8,
		},
		{
			name: "ipv6addr",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Addr,
				Length:   0,
			},
			expected: 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attr.GetMinimumLength()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttributeDefinition_GetMaximumLength(t *testing.T) {
	tests := []struct {
		name     string
		attr     *AttributeDefinition
		expected int
	}{
		{
			name: "fixed-length string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   10,
			},
			expected: 10,
		},
		{
			name: "variable-length string",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   0,
			},
			expected: 253,
		},
		{
			name: "integer",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
				Length:   0,
			},
			expected: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attr.GetMaximumLength()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestAttributeDefinition_FormatValue(t *testing.T) {
	tests := []struct {
		name     string
		attr     *AttributeDefinition
		value    []byte
		expected string
	}{
		{
			name: "string value",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   0,
			},
			value:    []byte("hello"),
			expected: "hello",
		},
		{
			name: "fixed-length string with padding",
			attr: &AttributeDefinition{
				DataType: DataTypeString,
				Length:   10,
			},
			value:    []byte("hello\x00\x00\x00\x00\x00"),
			expected: "hello",
		},
		{
			name: "octets value",
			attr: &AttributeDefinition{
				DataType: DataTypeOctets,
				Length:   0,
			},
			value:    []byte{0x01, 0x02, 0x03},
			expected: "0x010203",
		},
		{
			name: "integer value",
			attr: &AttributeDefinition{
				DataType: DataTypeInteger,
				Length:   0,
			},
			value:    []byte{0x00, 0x00, 0x03, 0xe8}, // 1000 in big-endian
			expected: "1000",
		},
		{
			name: "ipaddr value",
			attr: &AttributeDefinition{
				DataType: DataTypeIPAddr,
				Length:   0,
			},
			value:    []byte{192, 168, 1, 1},
			expected: "192.168.1.1",
		},
		{
			name: "ipv6addr value",
			attr: &AttributeDefinition{
				DataType: DataTypeIPv6Addr,
				Length:   0,
			},
			value:    []byte{0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			expected: "2001:db8:0:0:0:0:0:1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.attr.FormatValue(tt.value)
			assert.Equal(t, tt.expected, result)
		})
	}
}
