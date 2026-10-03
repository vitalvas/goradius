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

	// Verify Juniper vendor is loaded (ID 2636)
	juniperVendor, ok := dict.LookupVendorByID(2636)
	assert.True(t, ok, "Juniper vendor (ID 2636) should be loaded")
	if ok {
		assert.Equal(t, "juniper", juniperVendor.Name)
		juniperAttr, ok := dict.LookupVendorAttributeByID(2636, 1)
		assert.True(t, ok, "juniper-local-user-name should be loaded")
		if ok {
			assert.Equal(t, "juniper-local-user-name", juniperAttr.Name)
		}

		// Verify lookup by name also works (using unified lookup)
		juniperAttrByName, ok := dict.LookupByAttributeName("juniper-user-permissions")
		assert.True(t, ok, "juniper-user-permissions should be found by name")
		if ok {
			assert.Equal(t, uint32(10), juniperAttrByName.ID)
		}
	}

	// Verify ERX vendor is loaded (ID 4874)
	erxVendor, ok := dict.LookupVendorByID(4874)
	assert.True(t, ok, "ERX vendor (ID 4874) should be loaded")
	if ok {
		assert.Equal(t, "erx", erxVendor.Name)
	}

	// Verify Ascend vendor is loaded (ID 529)
	ascendVendor, ok := dict.LookupVendorByID(529)
	assert.True(t, ok, "Ascend vendor (ID 529) should be loaded")
	if ok {
		assert.Equal(t, "ascend", ascendVendor.Name)
	}

	// Verify WISPr vendor is loaded (ID 14122)
	wisprVendor, ok := dict.LookupVendorByID(14122)
	assert.True(t, ok, "WISPr vendor (ID 14122) should be loaded")
	if ok {
		assert.Equal(t, "wispr", wisprVendor.Name)
	}

	// Verify Mikrotik vendor is loaded (ID 14988)
	mikrotikVendor, ok := dict.LookupVendorByID(14988)
	assert.True(t, ok, "Mikrotik vendor (ID 14988) should be loaded")
	if ok {
		assert.Equal(t, "mikrotik", mikrotikVendor.Name)
	}

	// Verify Cisco vendor is loaded (ID 9)
	ciscoVendor, ok := dict.LookupVendorByID(9)
	assert.True(t, ok, "Cisco vendor (ID 9) should be loaded")
	if ok {
		assert.Equal(t, "cisco", ciscoVendor.Name)
		ciscoAttr, ok := dict.LookupByAttributeName("cisco-avpair")
		assert.True(t, ok, "cisco-avpair should be found by name")
		if ok {
			assert.Equal(t, uint32(1), ciscoAttr.ID)
		}
	}

	// Verify F5 vendor is loaded (ID 3375)
	f5Vendor, ok := dict.LookupVendorByID(3375)
	assert.True(t, ok, "F5 vendor (ID 3375) should be loaded")
	if ok {
		assert.Equal(t, "f5", f5Vendor.Name)
		f5Attr, ok := dict.LookupByAttributeName("f5-ltm-user-role")
		assert.True(t, ok, "f5-ltm-user-role should be found by name")
		if ok {
			assert.Equal(t, uint32(1), f5Attr.ID)
		}
	}

	// Verify A10 vendor is loaded (ID 22610)
	a10Vendor, ok := dict.LookupVendorByID(22610)
	assert.True(t, ok, "A10 vendor (ID 22610) should be loaded")
	if ok {
		assert.Equal(t, "a10", a10Vendor.Name)
		a10Attr, ok := dict.LookupByAttributeName("a10-admin-privilege")
		assert.True(t, ok, "a10-admin-privilege should be found by name")
		if ok {
			assert.Equal(t, uint32(2), a10Attr.ID)
		}
	}

	// Verify Arista vendor is loaded (ID 30065)
	aristaVendor, ok := dict.LookupVendorByID(30065)
	assert.True(t, ok, "Arista vendor (ID 30065) should be loaded")
	if ok {
		assert.Equal(t, "arista", aristaVendor.Name)
		aristaAttr, ok := dict.LookupByAttributeName("arista-avpair")
		assert.True(t, ok, "arista-avpair should be found by name")
		if ok {
			assert.Equal(t, uint32(1), aristaAttr.ID)
		}
	}

	// Verify Arista WiFi vendor is loaded (ID 16901)
	aristaWiFiVendor, ok := dict.LookupVendorByID(16901)
	assert.True(t, ok, "Arista WiFi vendor (ID 16901) should be loaded")
	if ok {
		assert.Equal(t, "arista-wifi", aristaWiFiVendor.Name)
		wifiAttr, ok := dict.LookupByAttributeName("arista-wifi-client-role")
		assert.True(t, ok, "arista-wifi-client-role should be found by name")
		if ok {
			assert.Equal(t, uint32(7), wifiAttr.ID)
		}
	}

	// Verify Ciena vendor is loaded (ID 1271)
	cienaVendor, ok := dict.LookupVendorByID(1271)
	assert.True(t, ok, "Ciena vendor (ID 1271) should be loaded")
	if ok {
		assert.Equal(t, "ciena", cienaVendor.Name)
		cienaAttr, ok := dict.LookupByAttributeName("ciena-ces-priv-level")
		assert.True(t, ok, "ciena-ces-priv-level should be found by name")
		if ok {
			assert.Equal(t, uint32(10), cienaAttr.ID)
		}
	}

	// Verify Benu vendor is loaded (ID 39406)
	benuVendor, ok := dict.LookupVendorByID(39406)
	assert.True(t, ok, "Benu vendor (ID 39406) should be loaded")
	if ok {
		assert.Equal(t, "benu", benuVendor.Name)
		benuAttr, ok := dict.LookupByAttributeName("benu-subscriber-id")
		assert.True(t, ok, "benu-subscriber-id should be found by name")
		if ok {
			assert.Equal(t, uint32(43), benuAttr.ID)
		}
	}

	// Verify GetAllVendors works
	allVendors := dict.GetAllVendors()
	assert.GreaterOrEqual(t, len(allVendors), 14, "Should have at least 14 vendors loaded")
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
