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
	fmt.Printf("Received %s from %s\n", req.Packet.Code.String(), req.RemoteAddr)

	resp := server.NewResponse(req)

	attrs := map[string]interface{}{
		"Reply-Message":          "Hello, RADIUS client!",
		"ERX-Service-Activate:1": "ipoe-parking",
		"ERX-Service-Activate:3": "svc-ipoe-policer(52428800, 52428800)",
	}

	resp.SetAttributes(attrs)

	resp.SetAttribute("Framed-Pool", "dhcp-pool-cgnat")

	switch req.Packet.Code {
	case packet.CodeAccessRequest:
		resp.SetCode(packet.CodeAccessAccept)
	case packet.CodeAccountingRequest:
		resp.SetCode(packet.CodeAccountingResponse)
	}

	return resp, nil
}

func main() {
	// Create dictionary with standard RFC definitions
	dict := dictionary.New()
	dict.AddStandardAttributes(dictionaries.StandardRFCAttributes)

	srv, err := server.New(":1812", &simpleHandler{}, dict)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("RADIUS server listening on :1812")
	log.Fatal(srv.Serve())
}
