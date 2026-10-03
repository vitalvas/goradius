package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestERXVendorDefinition(t *testing.T) {
	assert.NotNil(t, ERXVendorDefinition)
	assert.Equal(t, uint32(4874), ERXVendorDefinition.ID)
	assert.Equal(t, "erx", ERXVendorDefinition.Name)
	assert.NotEmpty(t, ERXVendorDefinition.Attributes)

	// Check some known ERX attributes
	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range ERXVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	// Verify ERX-Service-Activate exists and has tag
	serviceActivate, exists := attrMap["erx-service-activate"]
	assert.True(t, exists, "ERX-Service-Activate should exist")
	if exists {
		assert.True(t, serviceActivate.HasTag, "ERX-Service-Activate should support tags")
		assert.Equal(t, DataTypeString, serviceActivate.DataType)
	}

	// Verify ERX-Primary-Dns exists
	primaryDNS, exists := attrMap["erx-primary-dns"]
	assert.True(t, exists, "ERX-Primary-Dns should exist")
	if exists {
		assert.Equal(t, DataTypeIPAddr, primaryDNS.DataType)
	}

	// The Junos 18.4 dictionary defines Tunnel-Max-Sessions as tagged (1-31)
	maxSessions, exists := attrMap["erx-tunnel-maximum-sessions"]
	assert.True(t, exists)
	if exists {
		assert.True(t, maxSessions.HasTag, "tunnel-maximum-sessions should support tags")
	}

	// Both Juniper sources define Framed-Ip-Route-Tag as a 4-octet integer
	routeTag, exists := attrMap["erx-framed-ip-route-tag"]
	assert.True(t, exists)
	if exists {
		assert.Equal(t, DataTypeInteger, routeTag.DataType)
	}

	// IDs reused by Junos OS Evolved (policer and queue counters) must stay
	// unrestricted so both platform meanings remain usable
	for _, name := range []string{
		"erx-ingress-statistics", "erx-atm-pcr", "erx-cli-initial-access-level",
		"erx-qos-profile-interface-type", "erx-tunnel-tos",
		"sdx-service-name", "sdx-session-volume-quota",
	} {
		attr, ok := attrMap[name]
		assert.True(t, ok, name)
		if ok {
			assert.Equal(t, AttributeUsage(0), attr.Usage, "%s must stay unrestricted", name)
		}
	}
}

func TestNoDuplicateERXAttributeIDs(t *testing.T) {
	seen := make(map[uint32]string)

	for _, attr := range ERXVendorDefinition.Attributes {
		if existing, exists := seen[attr.ID]; exists {
			t.Errorf("Duplicate ERX attribute ID %d: %s and %s", attr.ID, existing, attr.Name)
		}
		seen[attr.ID] = attr.Name
	}
}
