package main

import (
	"fmt"
	"log"

	"github.com/vitalvas/goradius/pkg/dictionaries"
	"github.com/vitalvas/goradius/pkg/dictionary"
	"github.com/vitalvas/goradius/pkg/packet"
	"github.com/vitalvas/goradius/pkg/server"
)

type simpleHandler struct{}

func (h *simpleHandler) ServeSecret(req server.SecretRequest) (server.SecretResponse, error) {
	fmt.Printf("Received secret request from %s\n", req.RemoteAddr)

	return server.SecretResponse{
		Secret: []byte("testing123"),
		Metadata: map[string]interface{}{
			"client":  req.RemoteAddr.String(),
			"nastype": "generic",
		},
	}, nil
}

func (h *simpleHandler) ServeRADIUS(req *server.Request) (server.Response, error) {
	fmt.Printf("Received %s from %s\n", req.Code().String(), req.RemoteAddr)

	// Access metadata from the secret response
	if nastype, ok := req.Secret.Metadata["nastype"].(string); ok {
		fmt.Printf("NAS Type: %s\n", nastype)
	}
	if client, ok := req.Secret.Metadata["client"].(string); ok {
		fmt.Printf("Client: %s\n", client)
	}

	// List all attributes in the request
	attrList := req.ListAttributes()
	if len(attrList) > 0 {
		fmt.Println("Request attributes:", attrList)
	}

	// Example: Get specific attributes
	if userValues := req.GetAttribute("User-Name"); len(userValues) > 0 {
		fmt.Printf("Username: %s\n", userValues[0].String())
	}

	if nasIPValues := req.GetAttribute("NAS-IP-Address"); len(nasIPValues) > 0 {
		fmt.Printf("NAS IP: %s\n", nasIPValues[0].String())
	}

	resp := server.NewResponse(req)

	// Set appropriate response code based on request type
	switch req.Code() {
	case packet.CodeAccessRequest:
		resp.SetCode(packet.CodeAccessAccept)
	case packet.CodeAccountingRequest:
		resp.SetCode(packet.CodeAccountingResponse)
	}

	attrs := map[string]interface{}{
		"Reply-Message":           "Hello, RADIUS client!",
		"ERX-Service-Activate:1":  "ipoe-parking",
		"ERX-Service-Activate:3":  "svc-ipoe-policer(52428800, 52428800)",
		"ERX-Primary-Dns":         "8.8.8.8",
		"ERX-Ingress-Policy-Name": "svc-ipoe-filter",
		"Framed-IP-Address":       "192.0.2.11",
	}

	if err := resp.SetAttributes(attrs); err != nil {
		return resp, fmt.Errorf("failed to set attributes: %w", err)
	}

	if err := resp.SetAttribute("Framed-Pool", "dhcp-pool-cgnat"); err != nil {
		return resp, fmt.Errorf("failed to set Framed-Pool: %w", err)
	}
	// if err := resp.SetAttribute("Framed-Pool", "dhcp-pool-cgnat-v2"); err != nil {
	//     return resp, fmt.Errorf("failed to set Framed-Pool: %w", err)
	// }

	// expected response SetAttributes + SetAttribute
	return resp, nil
}

func main() {
	// Create dictionary with standard RFC definitions
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)
	dict.AddVendor(dictionaries.ERXVendorDefinition)

	srv, err := server.New(":1812", &simpleHandler{}, dict)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RADIUS server listening on :1812")
	log.Fatal(srv.Serve())
}
