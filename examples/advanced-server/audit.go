//yake:skip-test
package main

import (
	"encoding/json"
	"io"
	"time"

	"go.vitalvas.com/goradius"
)

type AuditLog struct {
	Timestamp string      `json:"timestamp"`
	Remote    string      `json:"remote"`
	Local     string      `json:"local"`
	Request   AuditPacket `json:"request"`
	Response  AuditPacket `json:"response"`
}

type AuditPacket struct {
	Code       string              `json:"code"`
	Attributes map[string][]string `json:"attributes"`
}

func auditMiddleware(writer io.Writer) goradius.Middleware {
	return func(next goradius.Handler) goradius.Handler {
		return goradius.HandlerFunc(func(req *goradius.Request) (goradius.Response, error) {
			resp, err := next.ServeRADIUS(req)

			auditLog := AuditLog{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Remote:    req.RemoteAddr.String(),
				Local:     req.LocalAddr.String(),
				Request: AuditPacket{
					Code:       req.Code().String(),
					Attributes: req.GetAttributeStrings(),
				},
				Response: AuditPacket{
					Code:       resp.Code().String(),
					Attributes: resp.GetAttributeStrings(),
				},
			}

			if data, marshalErr := json.Marshal(auditLog); marshalErr == nil {
				writer.Write(data)
				writer.Write([]byte("\n"))
			}

			return resp, err
		})
	}
}
