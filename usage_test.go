package goradius

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsageForCode(t *testing.T) {
	cases := map[Code]AttributeUsage{
		CodeAccessRequest:      UsageAccessRequest,
		CodeAccessAccept:       UsageAccessAccept,
		CodeAccessReject:       UsageAccessReject,
		CodeAccessChallenge:    UsageAccessChallenge,
		CodeAccountingRequest:  UsageAccountingRequest,
		CodeAccountingResponse: UsageAccountingResponse,
		CodeCoARequest:         UsageCoARequest,
		CodeCoAACK:             UsageCoAACK,
		CodeCoANAK:             UsageCoANAK,
		CodeDisconnectRequest:  UsageDisconnectRequest,
		CodeDisconnectACK:      UsageDisconnectACK,
		CodeDisconnectNAK:      UsageDisconnectNAK,
	}

	seen := make(map[AttributeUsage]bool)
	for code, want := range cases {
		got := UsageForCode(code)
		assert.Equal(t, want, got, "code %s", code)
		assert.False(t, seen[got], "bit for %s must be unique", code)
		seen[got] = true
	}

	assert.Equal(t, AttributeUsage(0), UsageForCode(CodeStatusServer))
}

func TestAllowedIn(t *testing.T) {
	t.Run("usage mask is authoritative", func(t *testing.T) {
		attr := &AttributeDefinition{
			Name:     "x",
			DataType: DataTypeString,
			Usage:    UsageAccessRequest | UsageCoARequest,
		}
		assert.True(t, attr.AllowedIn(CodeAccessRequest))
		assert.True(t, attr.AllowedIn(CodeCoARequest))
		assert.False(t, attr.AllowedIn(CodeAccessAccept))
		assert.False(t, attr.AllowedIn(CodeAccountingRequest))
		assert.False(t, attr.AllowedIn(CodeDisconnectRequest))
	})

	t.Run("zero usage is unrestricted", func(t *testing.T) {
		attr := &AttributeDefinition{Name: "b"}
		assert.True(t, attr.AllowedIn(CodeAccessRequest))
		assert.True(t, attr.AllowedIn(CodeAccessAccept))
		assert.True(t, attr.AllowedIn(CodeCoANAK))
	})

	t.Run("request and response combos", func(t *testing.T) {
		request := &AttributeDefinition{
			Name:  "r",
			Usage: UsageAllRequests,
		}
		assert.True(t, request.AllowedIn(CodeAccessRequest))
		assert.True(t, request.AllowedIn(CodeCoARequest))
		assert.False(t, request.AllowedIn(CodeAccessAccept))
		assert.False(t, request.AllowedIn(CodeDisconnectNAK))

		reply := &AttributeDefinition{
			Name:  "p",
			Usage: UsageAllResponses,
		}
		assert.False(t, reply.AllowedIn(CodeAccessRequest))
		assert.True(t, reply.AllowedIn(CodeAccessAccept))
		assert.True(t, reply.AllowedIn(CodeDisconnectNAK))
	})

	t.Run("codes without a usage bit are unrestricted", func(t *testing.T) {
		attr := &AttributeDefinition{
			Name:  "s",
			Usage: UsageAccessRequest,
		}
		assert.True(t, attr.AllowedIn(CodeStatusServer))
	})
}

// TestDictionaryUsageMasks spot-checks the masks injected from the RFC
// "Table of Attributes" sections against the default dictionary.
func TestDictionaryUsageMasks(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	lookup := func(name string) *AttributeDefinition {
		attr, ok := dict.LookupStandardByName(name)
		require.True(t, ok, name)
		return attr
	}

	t.Run("user-password only in access-request", func(t *testing.T) {
		attr := lookup("user-password")
		assert.True(t, attr.AllowedIn(CodeAccessRequest))
		assert.False(t, attr.AllowedIn(CodeAccessAccept))
		assert.False(t, attr.AllowedIn(CodeAccountingRequest))
		assert.False(t, attr.AllowedIn(CodeCoARequest))
	})

	t.Run("reply-message never in access-request", func(t *testing.T) {
		attr := lookup("reply-message")
		assert.False(t, attr.AllowedIn(CodeAccessRequest))
		assert.True(t, attr.AllowedIn(CodeAccessReject))
		assert.True(t, attr.AllowedIn(CodeAccessChallenge))
	})

	t.Run("acct-status-type only in accounting-request", func(t *testing.T) {
		attr := lookup("acct-status-type")
		assert.True(t, attr.AllowedIn(CodeAccountingRequest))
		assert.False(t, attr.AllowedIn(CodeAccessRequest))
		assert.False(t, attr.AllowedIn(CodeAccountingResponse))
	})

	t.Run("error-cause only in nak responses", func(t *testing.T) {
		attr := lookup("error-cause")
		assert.True(t, attr.AllowedIn(CodeCoANAK))
		assert.True(t, attr.AllowedIn(CodeDisconnectNAK))
		assert.False(t, attr.AllowedIn(CodeCoARequest))
		assert.False(t, attr.AllowedIn(CodeCoAACK))
		assert.False(t, attr.AllowedIn(CodeAccessAccept))
	})

	t.Run("event-timestamp in dynamic authorization", func(t *testing.T) {
		attr := lookup("event-timestamp")
		assert.True(t, attr.AllowedIn(CodeDisconnectRequest))
		assert.True(t, attr.AllowedIn(CodeDisconnectACK))
		assert.True(t, attr.AllowedIn(CodeAccountingRequest))
		assert.False(t, attr.AllowedIn(CodeAccessRequest))
	})

	t.Run("state in challenge and coa", func(t *testing.T) {
		attr := lookup("state")
		assert.True(t, attr.AllowedIn(CodeAccessChallenge))
		assert.True(t, attr.AllowedIn(CodeCoANAK))
		assert.False(t, attr.AllowedIn(CodeAccessReject))
		assert.False(t, attr.AllowedIn(CodeDisconnectRequest))
	})

	t.Run("erx service attributes in accept and coa", func(t *testing.T) {
		attr, ok := dict.LookupByAttributeName("erx-service-activate")
		require.True(t, ok)
		assert.True(t, attr.AllowedIn(CodeAccessAccept))
		assert.True(t, attr.AllowedIn(CodeCoARequest))
		assert.False(t, attr.AllowedIn(CodeAccessRequest))

		update, ok := dict.LookupByAttributeName("erx-update-service")
		require.True(t, ok)
		assert.True(t, update.AllowedIn(CodeCoARequest))
		assert.False(t, update.AllowedIn(CodeAccessAccept))
	})

	t.Run("erx dns only in accept", func(t *testing.T) {
		attr, ok := dict.LookupByAttributeName("erx-primary-dns")
		require.True(t, ok)
		assert.True(t, attr.AllowedIn(CodeAccessAccept))
		assert.False(t, attr.AllowedIn(CodeAccessRequest))
		assert.False(t, attr.AllowedIn(CodeAccountingRequest))
	})

	t.Run("dsl forum access line identification", func(t *testing.T) {
		circuit, ok := dict.LookupByAttributeName("adsl-agent-circuit-id")
		require.True(t, ok)
		assert.True(t, circuit.AllowedIn(CodeAccessRequest))
		assert.True(t, circuit.AllowedIn(CodeAccountingRequest))
		assert.True(t, circuit.AllowedIn(CodeCoARequest))
		assert.False(t, circuit.AllowedIn(CodeAccessAccept))

		dslType, ok := dict.LookupByAttributeName("adsl-dsl-type")
		require.True(t, ok)
		assert.True(t, dslType.AllowedIn(CodeAccessRequest))
		assert.False(t, dslType.AllowedIn(CodeCoARequest))
	})

	t.Run("microsoft per rfc 2548", func(t *testing.T) {
		sendKey, ok := dict.LookupByAttributeName("ms-mppe-send-key")
		require.True(t, ok)
		assert.True(t, sendKey.AllowedIn(CodeAccessAccept))
		assert.False(t, sendKey.AllowedIn(CodeAccessRequest))

		challenge, ok := dict.LookupByAttributeName("ms-chap-challenge")
		require.True(t, ok)
		assert.True(t, challenge.AllowedIn(CodeAccessRequest))
		assert.True(t, challenge.AllowedIn(CodeAccessChallenge))
		assert.False(t, challenge.AllowedIn(CodeAccessAccept))
	})

	t.Run("cisco per vsaig3 and isg guides", func(t *testing.T) {
		confID, ok := dict.LookupByAttributeName("cisco-h323-conf-id")
		require.True(t, ok)
		assert.True(t, confID.AllowedIn(CodeAccessRequest))
		assert.True(t, confID.AllowedIn(CodeAccountingRequest))
		assert.False(t, confID.AllowedIn(CodeAccessAccept))

		creditTime, ok := dict.LookupByAttributeName("cisco-h323-credit-time")
		require.True(t, ok)
		assert.True(t, creditTime.AllowedIn(CodeAccessAccept))
		assert.False(t, creditTime.AllowedIn(CodeAccessRequest))
		assert.False(t, creditTime.AllowedIn(CodeAccountingResponse))

		callID, ok := dict.LookupByAttributeName("cisco-call-id")
		require.True(t, ok)
		assert.True(t, callID.AllowedIn(CodeAccountingRequest))
		assert.False(t, callID.AllowedIn(CodeAccessRequest))

		commandCode, ok := dict.LookupByAttributeName("cisco-command-code")
		require.True(t, ok)
		assert.True(t, commandCode.AllowedIn(CodeCoARequest))
		assert.False(t, commandCode.AllowedIn(CodeAccessAccept))

		accountInfo, ok := dict.LookupByAttributeName("cisco-account-info")
		require.True(t, ok)
		assert.True(t, accountInfo.AllowedIn(CodeAccessAccept))
		assert.True(t, accountInfo.AllowedIn(CodeCoARequest))
		assert.False(t, accountInfo.AllowedIn(CodeDisconnectRequest))

		avPair, ok := dict.LookupByAttributeName("cisco-avpair")
		require.True(t, ok)
		assert.Equal(t, AttributeUsage(0), avPair.Usage, "generic container stays unrestricted")
	})

	t.Run("juniper per user-access docs", func(t *testing.T) {
		allow, ok := dict.LookupByAttributeName("juniper-allow-commands")
		require.True(t, ok)
		assert.True(t, allow.AllowedIn(CodeAccessAccept))
		assert.False(t, allow.AllowedIn(CodeAccessRequest))
		assert.False(t, allow.AllowedIn(CodeAccountingRequest))

		command, ok := dict.LookupByAttributeName("juniper-interactive-command")
		require.True(t, ok)
		assert.True(t, command.AllowedIn(CodeAccountingRequest))
		assert.False(t, command.AllowedIn(CodeAccessAccept))

		avPair, ok := dict.LookupByAttributeName("juniper-av-pair")
		require.True(t, ok)
		assert.True(t, avPair.AllowedIn(CodeAccessAccept))
		assert.True(t, avPair.AllowedIn(CodeCoARequest))
		assert.False(t, avPair.AllowedIn(CodeAccessRequest))
	})

	t.Run("mikrotik per router-os docs", func(t *testing.T) {
		rateLimit, ok := dict.LookupByAttributeName("mikrotik-rate-limit")
		require.True(t, ok)
		assert.True(t, rateLimit.AllowedIn(CodeAccessAccept))
		assert.True(t, rateLimit.AllowedIn(CodeCoARequest))
		assert.False(t, rateLimit.AllowedIn(CodeAccessRequest))

		realm, ok := dict.LookupByAttributeName("mikrotik-realm")
		require.True(t, ok)
		assert.True(t, realm.AllowedIn(CodeAccessRequest))
		assert.True(t, realm.AllowedIn(CodeAccountingRequest))
		assert.False(t, realm.AllowedIn(CodeAccessAccept))

		comment, ok := dict.LookupByAttributeName("mikrotik-wireless-comment")
		require.True(t, ok)
		assert.Equal(t, AttributeUsage(0), comment.Usage, "undocumented placement stays unrestricted")
	})

	t.Run("wispr per wba tables", func(t *testing.T) {
		redirect, ok := dict.LookupByAttributeName("wispr-redirection-url")
		require.True(t, ok)
		assert.True(t, redirect.AllowedIn(CodeAccessAccept))
		assert.False(t, redirect.AllowedIn(CodeAccessRequest))

		bandwidth, ok := dict.LookupByAttributeName("wispr-bandwidth-max-down")
		require.True(t, ok)
		assert.True(t, bandwidth.AllowedIn(CodeAccessRequest))
		assert.True(t, bandwidth.AllowedIn(CodeAccessAccept))
		assert.True(t, bandwidth.AllowedIn(CodeAccountingRequest))
		assert.False(t, bandwidth.AllowedIn(CodeCoARequest))

		location, ok := dict.LookupByAttributeName("wispr-location-id")
		require.True(t, ok)
		assert.True(t, location.AllowedIn(CodeAccessRequest))
		assert.True(t, location.AllowedIn(CodeAccountingRequest))
		assert.False(t, location.AllowedIn(CodeAccessAccept))
	})

	t.Run("ascend per taos guide", func(t *testing.T) {
		dataFilter, ok := dict.LookupByAttributeName("ascend-data-filter")
		require.True(t, ok)
		assert.True(t, dataFilter.AllowedIn(CodeAccessAccept))
		assert.True(t, dataFilter.AllowedIn(CodeCoARequest))
		assert.False(t, dataFilter.AllowedIn(CodeAccessRequest))

		xmitRate, ok := dict.LookupByAttributeName("ascend-xmit-rate")
		require.True(t, ok)
		assert.True(t, xmitRate.AllowedIn(CodeAccessRequest))
		assert.True(t, xmitRate.AllowedIn(CodeAccountingRequest))
		assert.False(t, xmitRate.AllowedIn(CodeAccessAccept))

		maxTime, ok := dict.LookupByAttributeName("ascend-maximum-time")
		require.True(t, ok)
		assert.True(t, maxTime.AllowedIn(CodeAccessAccept))
		assert.False(t, maxTime.AllowedIn(CodeAccessRequest))
	})

	t.Run("message-authenticator everywhere", func(t *testing.T) {
		attr := lookup("message-authenticator")
		for _, code := range []Code{
			CodeAccessRequest, CodeAccessAccept, CodeAccessReject, CodeAccessChallenge,
			CodeAccountingRequest, CodeAccountingResponse,
			CodeCoARequest, CodeCoAACK, CodeCoANAK,
			CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		} {
			assert.True(t, attr.AllowedIn(code), code.String())
		}
	})
}

// TestPacketUsageFiltering verifies that the add path drops attributes that the
// usage mask forbids for the packet type, on both request and response packets.
func TestPacketUsageFiltering(t *testing.T) {
	dict, err := NewDefault()
	require.NoError(t, err)

	t.Run("accounting attribute skipped in access-request", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccessRequest, 1, dict)
		require.NoError(t, pkt.AddAttributeByName("acct-status-type", "start"))
		assert.Empty(t, pkt.Attributes)
	})

	t.Run("accounting attribute added in accounting-request", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeAccountingRequest, 1, dict)
		require.NoError(t, pkt.AddAttributeByName("acct-status-type", "start"))
		assert.Len(t, pkt.Attributes, 1)
	})

	t.Run("error-cause added in coa-nak only", func(t *testing.T) {
		nak := NewPacketWithDictionary(CodeCoANAK, 1, dict)
		require.NoError(t, nak.AddAttributeByName("error-cause", "session-context-not-found"))
		assert.Len(t, nak.Attributes, 1)

		req := NewPacketWithDictionary(CodeCoARequest, 1, dict)
		require.NoError(t, req.AddAttributeByName("error-cause", "session-context-not-found"))
		assert.Empty(t, req.Attributes)
	})

	t.Run("user-password skipped in coa-request", func(t *testing.T) {
		pkt := NewPacketWithDictionary(CodeCoARequest, 1, dict)
		require.NoError(t, pkt.AddAttributeByNameWithSecret("user-password", "secret", []byte("s"), [16]byte{}))
		assert.Empty(t, pkt.Attributes)
	})
}

func BenchmarkAllowedIn(b *testing.B) {
	attr := &AttributeDefinition{
		Name:  "bench",
		Usage: UsageAccessRequest | UsageAccountingRequest | UsageCoARequest,
	}
	b.ReportAllocs()
	for b.Loop() {
		_ = attr.AllowedIn(CodeAccountingRequest)
	}
}

func BenchmarkUsageForCode(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = UsageForCode(CodeCoARequest)
	}
}

// FuzzAllowedIn ensures the usage check never panics and stays consistent with
// the plain bitmask semantics for every code and mask combination.
func FuzzAllowedIn(f *testing.F) {
	f.Add(uint8(1), uint32(0))
	f.Add(uint8(43), uint32(0xffffffff))
	f.Add(uint8(255), uint32(1))

	f.Fuzz(func(t *testing.T, code uint8, usage uint32) {
		attr := &AttributeDefinition{
			Name:  "fuzz",
			Usage: AttributeUsage(usage),
		}

		got := attr.AllowedIn(Code(code))

		bit := UsageForCode(Code(code))
		if attr.Usage == 0 || bit == 0 {
			if !got {
				t.Fatalf("code %d usage %04x: unrestricted combination must be allowed", code, usage)
			}
			return
		}
		if want := attr.Usage&bit != 0; got != want {
			t.Fatalf("code %d usage %04x: got %v want %v", code, usage, got, want)
		}
	})
}
