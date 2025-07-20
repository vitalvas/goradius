package packet

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCodeString(t *testing.T) {
	tests := []struct {
		code     Code
		expected string
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
		{CodeCoAAck, "CoA-ACK"},
		{CodeCoANak, "CoA-NAK"},
		{Code(255), "Unknown(255)"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.code.String())
		})
	}
}

func TestCodeIsValid(t *testing.T) {
	validCodes := []Code{
		CodeAccessRequest, CodeAccessAccept, CodeAccessReject,
		CodeAccountingRequest, CodeAccountingResponse,
		CodeAccessChallenge, CodeStatusServer, CodeStatusClient,
		CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAAck, CodeCoANak,
	}

	for _, code := range validCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.True(t, code.IsValid())
		})
	}

	invalidCodes := []Code{0, 6, 7, 8, 9, 10, 14, 15, 255}
	for _, code := range invalidCodes {
		t.Run("invalid", func(t *testing.T) {
			assert.False(t, code.IsValid())
		})
	}
}

func TestCodeIsRequest(t *testing.T) {
	requestCodes := []Code{
		CodeAccessRequest, CodeAccountingRequest, CodeStatusServer,
		CodeDisconnectRequest, CodeCoARequest,
	}

	for _, code := range requestCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.True(t, code.IsRequest())
			assert.False(t, code.IsResponse())
		})
	}
}

func TestCodeIsResponse(t *testing.T) {
	responseCodes := []Code{
		CodeAccessAccept, CodeAccessReject, CodeAccessChallenge,
		CodeAccountingResponse, CodeStatusClient,
		CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoAAck, CodeCoANak,
	}

	for _, code := range responseCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.True(t, code.IsResponse())
			assert.False(t, code.IsRequest())
		})
	}
}

func TestCodeIsAccounting(t *testing.T) {
	accountingCodes := []Code{CodeAccountingRequest, CodeAccountingResponse}

	for _, code := range accountingCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.True(t, code.IsAccounting())
		})
	}

	nonAccountingCodes := []Code{CodeAccessRequest, CodeAccessAccept, CodeCoARequest}
	for _, code := range nonAccountingCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.False(t, code.IsAccounting())
		})
	}
}

func TestCodeIsAuthentication(t *testing.T) {
	authCodes := []Code{CodeAccessRequest, CodeAccessAccept, CodeAccessReject, CodeAccessChallenge}

	for _, code := range authCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.True(t, code.IsAuthentication())
		})
	}

	nonAuthCodes := []Code{CodeAccountingRequest, CodeCoARequest, CodeStatusServer}
	for _, code := range nonAuthCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.False(t, code.IsAuthentication())
		})
	}
}

func TestCodeIsCoA(t *testing.T) {
	coaCodes := []Code{
		CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
		CodeCoARequest, CodeCoAAck, CodeCoANak,
	}

	for _, code := range coaCodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.True(t, code.IsCoA())
		})
	}

	nonCoACodes := []Code{CodeAccessRequest, CodeAccountingRequest, CodeStatusServer}
	for _, code := range nonCoACodes {
		t.Run(code.String(), func(t *testing.T) {
			assert.False(t, code.IsCoA())
		})
	}
}

func TestCodeExpectedResponseCode(t *testing.T) {
	tests := []struct {
		request   Code
		responses []Code
	}{
		{
			CodeAccessRequest,
			[]Code{CodeAccessAccept, CodeAccessReject, CodeAccessChallenge},
		},
		{
			CodeAccountingRequest,
			[]Code{CodeAccountingResponse},
		},
		{
			CodeStatusServer,
			[]Code{CodeStatusClient},
		},
		{
			CodeDisconnectRequest,
			[]Code{CodeDisconnectACK, CodeDisconnectNAK},
		},
		{
			CodeCoARequest,
			[]Code{CodeCoAAck, CodeCoANak},
		},
		{
			CodeAccessAccept, // Response code should return nil
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.request.String(), func(t *testing.T) {
			responses := tt.request.ExpectedResponseCode()
			assert.Equal(t, tt.responses, responses)
		})
	}
}
