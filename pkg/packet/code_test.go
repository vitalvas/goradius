package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeString(t *testing.T) {
	tests := []struct {
		code Code
		want string
	}{
		{CodeAccessRequest, "Access-Request"},
		{CodeAccessAccept, "Access-Accept"},
		{CodeAccessReject, "Access-Reject"},
		{CodeAccountingRequest, "Accounting-Request"},
		{CodeAccountingResponse, "Accounting-Response"},
		{CodeAccessChallenge, "Access-Challenge"},
		{CodeStatusServer, "Status-Server"},
		{CodeStatusClient, "Status-Client"},
		{CodeDisconnectRequest, "Disconnect-Request"},
		{CodeDisconnectACK, "Disconnect-ACK"},
		{CodeDisconnectNAK, "Disconnect-NAK"},
		{CodeCoARequest, "CoA-Request"},
		{CodeCoAACK, "CoA-ACK"},
		{CodeCoANAK, "CoA-NAK"},
		{Code(99), "Unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.code.String())
		})
	}
}

func TestCodeIsValid(t *testing.T) {
	tests := []struct {
		name  string
		code  Code
		valid bool
	}{
		{"Access-Request", CodeAccessRequest, true},
		{"Access-Accept", CodeAccessAccept, true},
		{"Access-Reject", CodeAccessReject, true},
		{"Accounting-Request", CodeAccountingRequest, true},
		{"Accounting-Response", CodeAccountingResponse, true},
		{"Access-Challenge", CodeAccessChallenge, true},
		{"Status-Server", CodeStatusServer, true},
		{"Status-Client", CodeStatusClient, true},
		{"Disconnect-Request", CodeDisconnectRequest, true},
		{"Disconnect-ACK", CodeDisconnectACK, true},
		{"Disconnect-NAK", CodeDisconnectNAK, true},
		{"CoA-Request", CodeCoARequest, true},
		{"CoA-ACK", CodeCoAACK, true},
		{"CoA-NAK", CodeCoANAK, true},
		{"Invalid code 0", Code(0), false},
		{"Invalid code 99", Code(99), false},
		{"Invalid code 255", Code(255), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.code.IsValid())
		})
	}
}

func TestAllDefinedCodesAreValid(t *testing.T) {
	// Verify all defined codes are valid
	codes := []Code{
		CodeAccessRequest,
		CodeAccessAccept,
		CodeAccessReject,
		CodeAccountingRequest,
		CodeAccountingResponse,
		CodeAccessChallenge,
		CodeStatusServer,
		CodeStatusClient,
		CodeDisconnectRequest,
		CodeDisconnectACK,
		CodeDisconnectNAK,
		CodeCoARequest,
		CodeCoAACK,
		CodeCoANAK,
	}

	for _, code := range codes {
		t.Run(code.String(), func(t *testing.T) {
			assert.True(t, code.IsValid(), "code %d (%s) should be valid", code, code.String())
		})
	}
}
