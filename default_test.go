package goradius

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
	assert.True(t, ok, "user-name (ID 1) should be loaded")
	if ok {
		assert.Equal(t, "user-name", userNameAttr.Name)
	}

	// Verify standard RFC attributes are loaded by name
	userPassAttr, ok := dict.LookupStandardByName("user-password")
	assert.True(t, ok, "user-password should be loaded")
	if ok {
		assert.Equal(t, uint32(2), userPassAttr.ID)
		assert.Equal(t, "user-password", userPassAttr.Name)
	}

	// Each vendor: its ID, expected name, and one representative attribute
	// (name and ID) that must resolve through the unified lookup.
	vendors := []struct {
		id       uint32
		name     string
		attrName string
		attrID   uint32
	}{
		{2636, "juniper", "juniper-user-permissions", 10},
		{4874, "erx", "erx-service-activate", 65},
		{529, "ascend", "ascend-data-filter", 242},
		{14122, "wispr", "wispr-location-id", 1},
		{14988, "mikrotik", "mikrotik-rate-limit", 8},
		{9, "cisco", "cisco-avpair", 1},
		{3375, "f5", "f5-ltm-user-role", 1},
		{22610, "a10", "a10-admin-privilege", 2},
		{30065, "arista", "arista-avpair", 1},
		{16901, "arista-wifi", "arista-wifi-client-role", 7},
		{1271, "ciena", "ciena-ces-priv-level", 10},
		{39406, "benu", "benu-subscriber-id", 43},
		{3902, "zte", "zte-qos-profile-down", 82},
		{2011, "huawei", "huawei-avpair", 188},
		{3041, "alcatel", "aat-client-primary-dns", 5},
		{831, "alu-aaa", "alu-aaa-service-profile", 9},
		{637, "alcatel-esam", "alcatel-esam-vrf-name", 0x0700},
		{6527, "nokia-sr", "nokia-sr-sla-prof-str", 13},
		{2544, "adva", "adva-user-level", 100},
		{193, "ericsson", "ericsson-sitekeeper-name", 58},
		{2352, "ericsson-ab", "ericsson-ab-service-name", 190},
		{10923, "ericsson-pcn", "ericsson-pcn-suggested-rule-space", 30},
	}

	for _, v := range vendors {
		vendor, ok := dict.LookupVendorByID(v.id)
		assert.True(t, ok, "vendor %s (ID %d) should be loaded", v.name, v.id)
		if !ok {
			continue
		}
		assert.Equal(t, v.name, vendor.Name)

		attr, ok := dict.LookupByAttributeName(v.attrName)
		assert.True(t, ok, "%s should be found by name", v.attrName)
		if ok {
			assert.Equal(t, v.attrID, attr.ID, v.attrName)
		}
	}

	// Verify GetAllVendors works
	allVendors := dict.GetAllVendors()
	assert.GreaterOrEqual(t, len(allVendors), len(vendors), "all configured vendors should be loaded")
}

func TestNewDefaultMultilineAttributes(t *testing.T) {
	dict, err := NewDefault()
	assert.NoError(t, err)
	assert.NotNil(t, dict)

	// Verify Juniper multiline attributes are properly configured
	juniperUserPerms, ok := dict.LookupVendorAttributeByID(2636, 10)
	assert.True(t, ok, "juniper-user-permissions should exist")
	if ok {
		assert.Equal(t, "juniper-user-permissions", juniperUserPerms.Name)
		assert.True(t, juniperUserPerms.Multiline, "juniper-user-permissions should have multiline flag")
	}

	juniperAllowCmds, ok := dict.LookupVendorAttributeByID(2636, 2)
	assert.True(t, ok, "juniper-allow-commands should exist")
	if ok {
		assert.Equal(t, "juniper-allow-commands", juniperAllowCmds.Name)
		assert.True(t, juniperAllowCmds.Multiline, "juniper-allow-commands should have multiline flag")
	}
}

func TestNewDefaultEnumeratedValues(t *testing.T) {
	dict, err := NewDefault()
	assert.NoError(t, err)
	assert.NotNil(t, dict)

	// Verify Juniper-CTP-Group enumerated values
	ctpGroup, ok := dict.LookupVendorAttributeByID(2636, 21)
	assert.True(t, ok, "juniper-ctp-group should exist")
	if ok {
		assert.Equal(t, "juniper-ctp-group", ctpGroup.Name)
		assert.NotNil(t, ctpGroup.Values, "juniper-ctp-group should have enumerated values")
		if ctpGroup.Values != nil {
			assert.Equal(t, uint32(1), ctpGroup.Values["read_only"])
			assert.Equal(t, uint32(2), ctpGroup.Values["admin"])
			assert.Equal(t, uint32(3), ctpGroup.Values["privileged_admin"])
			assert.Equal(t, uint32(4), ctpGroup.Values["auditor"])
		}
	}

	// Verify Mikrotik-Wireless-Enc-Algo enumerated values
	encAlgo, ok := dict.LookupVendorAttributeByID(14988, 6)
	assert.True(t, ok, "mikrotik-wireless-enc-algo should exist")
	if ok {
		assert.Equal(t, "mikrotik-wireless-enc-algo", encAlgo.Name)
		assert.NotNil(t, encAlgo.Values, "mikrotik-wireless-enc-algo should have enumerated values")
		if encAlgo.Values != nil {
			assert.Equal(t, uint32(0), encAlgo.Values["no-encryption"])
			assert.Equal(t, uint32(1), encAlgo.Values["40-bit-wep"])
			assert.Equal(t, uint32(2), encAlgo.Values["104-bit-wep"])
			assert.Equal(t, uint32(3), encAlgo.Values["aes-ccm"])
			assert.Equal(t, uint32(4), encAlgo.Values["tkip"])
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
		_, _ = dict.LookupStandardByName("user-name")
	}
}

func BenchmarkNewDefaultLookupVendor(b *testing.B) {
	dict, _ := NewDefault()

	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		_, _ = dict.LookupByAttributeName("juniper-user-permissions")
	}
}
