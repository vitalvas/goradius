package dictionaries

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewDefault(t *testing.T) {
	dict, err := NewDefault()
	assert.NoError(t, err)
	assert.NotNil(t, dict)

	// Verify standard RFC attributes are loaded by ID
	userNameAttr, ok := dict.LookupStandardByID(1)
	assert.True(t, ok, "User-Name (ID 1) should be loaded")
	if ok {
		assert.Equal(t, "User-Name", userNameAttr.Name)
	}

	// Verify standard RFC attributes are loaded by name
	userPassAttr, ok := dict.LookupStandardByName("User-Password")
	assert.True(t, ok, "User-Password should be loaded")
	if ok {
		assert.Equal(t, uint32(2), userPassAttr.ID)
		assert.Equal(t, "User-Password", userPassAttr.Name)
	}

	// Verify Juniper vendor is loaded (ID 2636)
	juniperVendor, ok := dict.LookupVendorByID(2636)
	assert.True(t, ok, "Juniper vendor (ID 2636) should be loaded")
	if ok {
		assert.Equal(t, "Juniper", juniperVendor.Name)
		juniperAttr, ok := dict.LookupVendorAttributeByID(2636, 1)
		assert.True(t, ok, "Juniper-Local-User-Name should be loaded")
		if ok {
			assert.Equal(t, "Juniper-Local-User-Name", juniperAttr.Name)
		}

		// Verify lookup by name also works (using unified lookup)
		juniperAttrByName, ok := dict.LookupByAttributeName("Juniper-User-Permissions")
		assert.True(t, ok, "Juniper-User-Permissions should be found by name")
		if ok {
			assert.Equal(t, uint32(10), juniperAttrByName.ID)
		}
	}

	// Verify ERX vendor is loaded (ID 4874)
	erxVendor, ok := dict.LookupVendorByID(4874)
	assert.True(t, ok, "ERX vendor (ID 4874) should be loaded")
	if ok {
		assert.Equal(t, "ERX", erxVendor.Name)
	}

	// Verify Ascend vendor is loaded (ID 529)
	ascendVendor, ok := dict.LookupVendorByID(529)
	assert.True(t, ok, "Ascend vendor (ID 529) should be loaded")
	if ok {
		assert.Equal(t, "Ascend", ascendVendor.Name)
	}

	// Verify WISPr vendor is loaded (ID 14122)
	wisprVendor, ok := dict.LookupVendorByID(14122)
	assert.True(t, ok, "WISPr vendor (ID 14122) should be loaded")
	if ok {
		assert.Equal(t, "WISPr", wisprVendor.Name)
	}

	// Verify Mikrotik vendor is loaded (ID 14988)
	mikrotikVendor, ok := dict.LookupVendorByID(14988)
	assert.True(t, ok, "Mikrotik vendor (ID 14988) should be loaded")
	if ok {
		assert.Equal(t, "Mikrotik", mikrotikVendor.Name)
	}

	// Verify GetAllVendors works
	allVendors := dict.GetAllVendors()
	assert.GreaterOrEqual(t, len(allVendors), 5, "Should have at least 5 vendors loaded")
}

func TestNewDefaultMultilineAttributes(t *testing.T) {
	dict, err := NewDefault()
	assert.NoError(t, err)
	assert.NotNil(t, dict)

	// Verify Juniper multiline attributes are properly configured
	juniperUserPerms, ok := dict.LookupVendorAttributeByID(2636, 10)
	assert.True(t, ok, "Juniper-User-Permissions should exist")
	if ok {
		assert.Equal(t, "Juniper-User-Permissions", juniperUserPerms.Name)
		assert.True(t, juniperUserPerms.Multiline, "Juniper-User-Permissions should have multiline flag")
	}

	juniperAllowCmds, ok := dict.LookupVendorAttributeByID(2636, 2)
	assert.True(t, ok, "Juniper-Allow-Commands should exist")
	if ok {
		assert.Equal(t, "Juniper-Allow-Commands", juniperAllowCmds.Name)
		assert.True(t, juniperAllowCmds.Multiline, "Juniper-Allow-Commands should have multiline flag")
	}
}

func TestNewDefaultEnumeratedValues(t *testing.T) {
	dict, err := NewDefault()
	assert.NoError(t, err)
	assert.NotNil(t, dict)

	// Verify Juniper-CTP-Group enumerated values
	ctpGroup, ok := dict.LookupVendorAttributeByID(2636, 21)
	assert.True(t, ok, "Juniper-CTP-Group should exist")
	if ok {
		assert.Equal(t, "Juniper-CTP-Group", ctpGroup.Name)
		assert.NotNil(t, ctpGroup.Values, "Juniper-CTP-Group should have enumerated values")
		if ctpGroup.Values != nil {
			assert.Equal(t, uint32(1), ctpGroup.Values["Read_Only"])
			assert.Equal(t, uint32(2), ctpGroup.Values["Admin"])
			assert.Equal(t, uint32(3), ctpGroup.Values["Privileged_Admin"])
			assert.Equal(t, uint32(4), ctpGroup.Values["Auditor"])
		}
	}

	// Verify Mikrotik-Wireless-Enc-Algo enumerated values
	encAlgo, ok := dict.LookupVendorAttributeByID(14988, 6)
	assert.True(t, ok, "Mikrotik-Wireless-Enc-Algo should exist")
	if ok {
		assert.Equal(t, "Mikrotik-Wireless-Enc-Algo", encAlgo.Name)
		assert.NotNil(t, encAlgo.Values, "Mikrotik-Wireless-Enc-Algo should have enumerated values")
		if encAlgo.Values != nil {
			assert.Equal(t, uint32(0), encAlgo.Values["No-encryption"])
			assert.Equal(t, uint32(1), encAlgo.Values["40-bit-WEP"])
			assert.Equal(t, uint32(2), encAlgo.Values["104-bit-WEP"])
			assert.Equal(t, uint32(3), encAlgo.Values["AES-CCM"])
			assert.Equal(t, uint32(4), encAlgo.Values["TKIP"])
		}
	}
}

func BenchmarkNewDefault(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_, _ = NewDefault()
	}
}

func BenchmarkNewDefaultLookupStandard(b *testing.B) {
	dict, _ := NewDefault()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = dict.LookupStandardByName("User-Name")
	}
}

func BenchmarkNewDefaultLookupVendor(b *testing.B) {
	dict, _ := NewDefault()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = dict.LookupByAttributeName("Juniper-User-Permissions")
	}
}
