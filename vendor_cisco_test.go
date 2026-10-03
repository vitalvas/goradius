package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCiscoVendorDefinition(t *testing.T) {
	assert.NotNil(t, CiscoVendorDefinition)
	assert.Equal(t, uint32(9), CiscoVendorDefinition.ID)
	assert.Equal(t, "cisco", CiscoVendorDefinition.Name)
	assert.NotEmpty(t, CiscoVendorDefinition.Attributes)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range CiscoVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("cisco-avpair exists as string", func(t *testing.T) {
		a, ok := attrMap["cisco-avpair"]
		require.True(t, ok)
		assert.Equal(t, uint32(1), a.ID)
		assert.Equal(t, DataTypeString, a.DataType)
	})

	t.Run("cisco-nas-port exists as string", func(t *testing.T) {
		a, ok := attrMap["cisco-nas-port"]
		require.True(t, ok)
		assert.Equal(t, uint32(2), a.ID)
		assert.Equal(t, DataTypeString, a.DataType)
	})

	t.Run("cisco-account-info exists", func(t *testing.T) {
		a, ok := attrMap["cisco-account-info"]
		require.True(t, ok)
		assert.Equal(t, uint32(250), a.ID)
	})

	t.Run("cisco-command-code exists", func(t *testing.T) {
		a, ok := attrMap["cisco-command-code"]
		require.True(t, ok)
		assert.Equal(t, uint32(252), a.ID)
	})

	t.Run("cisco-disconnect-cause has enumerated values", func(t *testing.T) {
		a, ok := attrMap["cisco-disconnect-cause"]
		require.True(t, ok)
		assert.Equal(t, uint32(195), a.ID)
		assert.Equal(t, DataTypeInteger, a.DataType)
		require.NotNil(t, a.Values)
		assert.Equal(t, uint32(0), a.Values["no-reason"])
		assert.Equal(t, uint32(22), a.Values["exit-telnet-session"])
		assert.Equal(t, uint32(608), a.Values["vpn-call-redirect"])
	})

	t.Run("cisco-dhcp-client-id is octets", func(t *testing.T) {
		a, ok := attrMap["cisco-dhcp-client-id"]
		require.True(t, ok)
		assert.Equal(t, DataTypeOctets, a.DataType)
	})
}

func TestNoDuplicateCiscoAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)
	for _, attr := range CiscoVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate Cisco attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}

func TestNoDuplicateCiscoAttributeNames(t *testing.T) {
	seen := make(map[string]struct{})
	for _, attr := range CiscoVendorDefinition.Attributes {
		if _, exists := seen[attr.Name]; exists {
			t.Errorf("Duplicate Cisco attribute name %q", attr.Name)
		}
		seen[attr.Name] = struct{}{}
	}
}

// TestCiscoAttributeCount locks the full port of the FreeRADIUS base dictionary.cisco
// (vendor ID 9). The base dictionary defines 111 ATTRIBUTE entries; if this count
// changes, the port and this expectation must be reviewed together.
func TestCiscoAttributeCount(t *testing.T) {
	assert.Len(t, CiscoVendorDefinition.Attributes, 111)
}

func TestCiscoSpotCheckTypes(t *testing.T) {
	byID := make(map[uint32]*AttributeDefinition)
	for _, attr := range CiscoVendorDefinition.Attributes {
		byID[attr.ID] = attr
	}

	cases := []struct {
		id       uint32
		name     string
		dataType DataType
	}{
		{1, "cisco-avpair", DataTypeString},
		{2, "cisco-nas-port", DataTypeString},
		{49, "cisco-dhcp-client-id", DataTypeOctets},
		{187, "cisco-multilink-id", DataTypeInteger},
		{194, "cisco-maximum-time", DataTypeInteger},
		{195, "cisco-disconnect-cause", DataTypeInteger},
		{250, "cisco-account-info", DataTypeString},
		{252, "cisco-command-code", DataTypeString},
		{255, "cisco-xmit-rate", DataTypeInteger},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attr, ok := byID[tc.id]
			require.True(t, ok)
			assert.Equal(t, tc.name, attr.Name)
			assert.Equal(t, tc.dataType, attr.DataType)
		})
	}
}

func TestCiscoRegisteredInDefault(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	vendor, ok := dict.LookupVendorByID(9)
	require.True(t, ok)
	assert.Equal(t, "cisco", vendor.Name)

	attr, ok := dict.LookupByAttributeName("cisco-avpair")
	require.True(t, ok)
	assert.Equal(t, uint32(1), attr.ID)
}
