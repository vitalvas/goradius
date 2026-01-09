package main

import (
	"fmt"
	"log"
	"net"

	"github.com/vitalvas/goradius"
)

type simpleHandler struct{}

func (h *simpleHandler) ServeSecret(req goradius.SecretRequest) (goradius.SecretResponse, error) {
	fmt.Printf("Received secret request from %s\n", req.RemoteAddr)

	return goradius.SecretResponse{
		Secret: []byte("testing123"),
		Metadata: map[string]interface{}{
			"client":  req.RemoteAddr.String(),
			"nastype": "generic",
		},
	}, nil
}

func (h *simpleHandler) ServeRADIUS(req *goradius.Request) (goradius.Response, error) {
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

	resp := goradius.NewResponse(req)

	// Set appropriate response code based on request type
	switch req.Code() {
	case goradius.CodeAccessRequest:
		resp.SetCode(goradius.CodeAccessAccept)
	case goradius.CodeAccountingRequest:
		resp.SetCode(goradius.CodeAccountingResponse)
	}

	attrs := map[string][]interface{}{
		"Reply-Message":           {"Hello, RADIUS client!"},
		"ERX-Service-Activate:1":  {"ipoe-parking"},
		"ERX-Service-Activate:3":  {"svc-ipoe-policer(52428800, 52428800)"},
		"ERX-Primary-Dns":         {"8.8.8.8"},
		"ERX-Ingress-Policy-Name": {"svc-ipoe-filter"},
		"Framed-IP-Address":       {"192.0.2.11"},
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

func validationMiddleware(next goradius.Handler) goradius.Handler {
	return goradius.HandlerFunc(func(req *goradius.Request) (goradius.Response, error) {
		if req.Code() != goradius.CodeAccessRequest {
			// do not response for non Access-Request packets
			return goradius.Response{}, nil
		}

		return next.ServeRADIUS(req)
	})
}

func main() {
	srv, err := goradius.NewServer(goradius.ServerConfig{
		Handler: &simpleHandler{},
	})
	if err != nil {
		log.Fatal(err)
	}

	srv.Use(validationMiddleware)

	// Create UDP listener
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 1812})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RADIUS server listening on :1812")
	transport := goradius.NewUDPTransport(conn)
	log.Fatal(srv.Serve(transport))
}
