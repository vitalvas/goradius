//yake:skip-test
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
		UserData: map[string]string{
			"client":  req.RemoteAddr.String(),
			"nastype": "generic",
		},
	}, nil
}

func (h *simpleHandler) ServeRADIUS(req *goradius.Request) (goradius.Response, error) {
	fmt.Printf("Received %s from %s\n", req.Code().String(), req.RemoteAddr)

	// Access user data from the secret response
	if nastype, ok := req.Secret.UserData["nastype"]; ok {
		fmt.Printf("NAS Type: %s\n", nastype)
	}
	if client, ok := req.Secret.UserData["client"]; ok {
		fmt.Printf("Client: %s\n", client)
	}

	// List all attributes in the request
	attrList := req.ListAttributes()
	if len(attrList) > 0 {
		fmt.Println("Request attributes:", attrList)
	}

	// Example: Get specific attributes
	if userValues := req.GetAttribute("user-name"); len(userValues) > 0 {
		fmt.Printf("Username: %s\n", userValues[0].String())
	}

	if nasIPValues := req.GetAttribute("nas-ip-address"); len(nasIPValues) > 0 {
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
		"reply-message":           {"Hello, RADIUS client!"},
		"erx-service-activate:1":  {"ipoe-parking"},
		"erx-service-activate:3":  {"svc-ipoe-policer(52428800, 52428800)"},
		"erx-primary-dns":         {"8.8.8.8"},
		"erx-ingress-policy-name": {"svc-ipoe-filter"},
		"framed-ip-address":       {"192.0.2.11"},
	}

	if err := resp.SetAttributes(attrs); err != nil {
		return resp, fmt.Errorf("failed to set attributes: %w", err)
	}

	if err := resp.SetAttribute("framed-pool", "dhcp-pool-cgnat"); err != nil {
		return resp, fmt.Errorf("failed to set Framed-Pool: %w", err)
	}
	// if err := resp.SetAttribute("framed-pool", "dhcp-pool-cgnat-v2"); err != nil {
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
	srv, err := goradius.NewServer(
		goradius.WithHandler(&simpleHandler{}),
	)
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
