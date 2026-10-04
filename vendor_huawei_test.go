package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHuaweiLeaseStructRoundTrip confirms the real registered Huawei DHCPv6
// lease struct VSA (byte/byte/integer/integer members) round-trips through the
// default dictionary.
func TestHuaweiLeaseStructRoundTrip(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	pkt := NewPacketWithDictionary(CodeAccessAccept, 7, dict)
	require.NoError(t, pkt.AddAttributeByName("huawei-ipv6-prefix-lease", map[string]any{
		"huawei-ipv6-prefix-lease-t1":                 uint8(50),
		"huawei-ipv6-prefix-lease-t2":                 uint8(80),
		"huawei-ipv6-prefix-lease-preferred-lifetime": uint32(3600),
		"huawei-ipv6-prefix-lease-valid-lifetime":     uint32(7200),
	}))

	raw, err := pkt.Encode()
	require.NoError(t, err)
	decoded, err := Decode(raw)
	require.NoError(t, err)
	decoded.Dict = dict

	vals := decoded.GetAttribute("huawei-ipv6-prefix-lease")
	require.Len(t, vals, 1)
	children, err := vals[0].Children()
	require.NoError(t, err)
	assert.Equal(t, uint8(50), children["huawei-ipv6-prefix-lease-t1"])
	assert.Equal(t, uint8(80), children["huawei-ipv6-prefix-lease-t2"])
	assert.Equal(t, uint32(3600), children["huawei-ipv6-prefix-lease-preferred-lifetime"])
	assert.Equal(t, uint32(7200), children["huawei-ipv6-prefix-lease-valid-lifetime"])
}

func TestHuaweiVendorDefinition(t *testing.T) {
	assert.NotNil(t, HuaweiVendorDefinition)
	assert.Equal(t, uint32(2011), HuaweiVendorDefinition.ID)
	assert.Equal(t, "huawei", HuaweiVendorDefinition.Name)
	assert.Len(t, HuaweiVendorDefinition.Attributes, 163)

	attrMap := make(map[string]*AttributeDefinition)
	for _, attr := range HuaweiVendorDefinition.Attributes {
		attrMap[attr.Name] = attr
	}

	t.Run("auth type values", func(t *testing.T) {
		auth, ok := attrMap["huawei-auth-type"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, auth.DataType)
		assert.Equal(t, uint32(1), auth.Values["ppp"])
		assert.Equal(t, uint32(3), auth.Values["dot1x"])
		assert.Equal(t, uint32(10), auth.Values["none"])
	})

	t.Run("master type corrections applied", func(t *testing.T) {
		forwarding, ok := attrMap["huawei-nat-port-forwarding"]
		require.True(t, ok)
		assert.Equal(t, DataTypeString, forwarding.DataType)

		subcause, ok := attrMap["huawei-acct-terminate-subcause"]
		require.True(t, ok)
		assert.Equal(t, DataTypeInteger, subcause.DataType)
	})

	t.Run("master only additions present", func(t *testing.T) {
		group, ok := attrMap["huawei-user-group-name"]
		require.True(t, ok)
		assert.Equal(t, uint32(251), group.ID)

		svc, ok := attrMap["huawei-user-service-type"]
		require.True(t, ok)
		assert.Equal(t, uint32(252), svc.ID)
	})

	t.Run("ipv6 and lease types", func(t *testing.T) {
		dns, ok := attrMap["huawei-dns-server-ipv6-address"]
		require.True(t, ok)
		assert.Equal(t, DataTypeIPv6Addr, dns.DataType)

		lease, ok := attrMap["huawei-ipv6-prefix-lease"]
		require.True(t, ok)
		assert.Equal(t, DataTypeStruct, lease.DataType)
		require.Len(t, lease.Children, 4)
		assert.Equal(t, DataTypeByte, lease.Children[0].DataType)
		assert.Equal(t, DataTypeByte, lease.Children[1].DataType)
		assert.Equal(t, DataTypeInteger, lease.Children[2].DataType)
		assert.Equal(t, DataTypeInteger, lease.Children[3].DataType)
	})

	t.Run("all attributes stay unrestricted", func(t *testing.T) {
		for _, attr := range HuaweiVendorDefinition.Attributes {
			assert.Equal(t, AttributeUsage(0), attr.Usage, attr.Name)
		}
	})

	t.Run("no duplicate ids", func(t *testing.T) {
		seen := make(map[uint32]string)
		for _, attr := range HuaweiVendorDefinition.Attributes {
			existing, exists := seen[attr.ID]
			assert.False(t, exists, "duplicate ID %d: %s and %s", attr.ID, existing, attr.Name)
			seen[attr.ID] = attr.Name
		}
	})
}
