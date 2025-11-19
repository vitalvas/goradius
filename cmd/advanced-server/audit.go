package main

import (
	"encoding/json"
	"io"
	"time"

	"github.com/vitalvas/goradius/pkg/server"
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

func auditMiddleware(writer io.Writer) server.Middleware {
	return func(next server.Handler) server.Handler {
		return server.HandlerFunc(func(req *server.Request) (server.Response, error) {
			resp, err := next.ServeRADIUS(req)

			auditLog := AuditLog{
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Remote:    req.RemoteAddr.String(),
				Local:     req.LocalAddr.String(),
				Request: AuditPacket{
					Code:       req.Code().String(),
					Attributes: collectAttributes(req),
				},
				Response: AuditPacket{
					Code:       resp.Code().String(),
					Attributes: collectAttributesFromResponse(&resp),
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

func collectAttributes(req *server.Request) map[string][]string {
	attrs := make(map[string][]string)

	for _, name := range req.ListAttributes() {
		values := req.GetAttribute(name)
		strValues := make([]string, len(values))
		for i, v := range values {
			strValues[i] = v.String()
		}
		attrs[name] = strValues
	}

	return attrs
}

func collectAttributesFromResponse(resp *server.Response) map[string][]string {
	attrs := make(map[string][]string)

	for _, name := range resp.ListAttributes() {
		values := resp.GetAttribute(name)
		strValues := make([]string, len(values))
		for i, v := range values {
			strValues[i] = v.String()
		}
		attrs[name] = strValues
	}

	return attrs
}
