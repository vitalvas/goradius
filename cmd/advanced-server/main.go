package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/vitalvas/goradius/pkg/packet"
	"github.com/vitalvas/goradius/pkg/server"
)

type advancedHandler struct{}

func (h *advancedHandler) ServeSecret(req server.SecretRequest) (server.SecretResponse, error) {
	fmt.Printf("[Secret] Request from %s\n", req.RemoteAddr)

	return server.SecretResponse{
		Secret: []byte("testing123"),
		Metadata: map[string]interface{}{
			"client":  req.RemoteAddr.String(),
			"nastype": "generic",
		},
	}, nil
}

func (h *advancedHandler) ServeRADIUS(req *server.Request) (server.Response, error) {
	fmt.Printf("[Handler] Processing %s from %s\n", req.Code().String(), req.RemoteAddr)

	// Get user information
	if userValues := req.GetAttribute("User-Name"); len(userValues) > 0 {
		fmt.Printf("[Handler] User: %s\n", userValues[0].String())
	}

	resp := server.NewResponse(req)

	// Set appropriate response code based on request type
	switch req.Code() {
	case packet.CodeAccessRequest:
		resp.SetCode(packet.CodeAccessAccept)
	case packet.CodeAccountingRequest:
		resp.SetCode(packet.CodeAccountingResponse)
	}

	// Add response attributes
	if err := resp.SetAttributes(map[string][]interface{}{
		"Reply-Message":           {"Access granted via advanced server"},
		"Session-Timeout":         {3600},
		"Framed-IP-Address":       {"192.0.2.100"},
		"ERX-Primary-Dns":         {"8.8.8.8"},
		"ERX-Ingress-Policy-Name": {"premium-user-policy"},
	}); err != nil {
		return resp, fmt.Errorf("failed to set response attributes: %w", err)
	}

	return resp, nil
}

// Logging middleware
func loggingMiddleware(next server.Handler) server.Handler {
	return server.HandlerFunc(func(req *server.Request) (server.Response, error) {
		start := time.Now()

		fmt.Printf("[Middleware:Logging] >>> Request started: %s from %s\n",
			req.Code().String(), req.RemoteAddr)

		resp, err := next.ServeRADIUS(req)

		duration := time.Since(start)
		if err != nil {
			fmt.Printf("[Middleware:Logging] <<< Request failed in %v: %v\n", duration, err)
		} else {
			fmt.Printf("[Middleware:Logging] <<< Request completed in %v: %s\n",
				duration, resp.Code().String())
		}

		return resp, err
	})
}

// Attribute listing middleware
func attributeListMiddleware(next server.Handler) server.Handler {
	return server.HandlerFunc(func(req *server.Request) (server.Response, error) {
		attrs := req.ListAttributes()
		if len(attrs) > 0 {
			fmt.Printf("[Middleware:Attributes] Request contains: %v\n", attrs)

			// Print detailed attribute values
			for _, attrName := range attrs {
				values := req.GetAttribute(attrName)
				for i, val := range values {
					fmt.Printf("[Middleware:Attributes]   %s[%d] = %s (type: %s)\n",
						attrName, i, val.String(), val.DataType)
				}
			}
		}

		return next.ServeRADIUS(req)
	})
}

// Validation middleware
func validationMiddleware(next server.Handler) server.Handler {
	return server.HandlerFunc(func(req *server.Request) (server.Response, error) {
		// Validate User-Name is present for Access-Request
		if req.Code() == packet.CodeAccessRequest {
			userValues := req.GetAttribute("User-Name")
			if len(userValues) == 0 {
				fmt.Println("[Middleware:Validation] ERROR: User-Name is required")
				// Return Access-Reject
				resp := server.NewResponse(req)
				resp.SetCode(packet.CodeAccessReject)
				if err := resp.SetAttribute("Reply-Message", "User-Name is required"); err != nil {
					return resp, fmt.Errorf("failed to set Reply-Message: %w", err)
				}
				return resp, nil
			}

			username := userValues[0].String()
			if len(username) == 0 {
				fmt.Println("[Middleware:Validation] ERROR: User-Name cannot be empty")
				resp := server.NewResponse(req)
				resp.SetCode(packet.CodeAccessReject)
				if err := resp.SetAttribute("Reply-Message", "User-Name cannot be empty"); err != nil {
					return resp, fmt.Errorf("failed to set Reply-Message: %w", err)
				}
				return resp, nil
			}

			fmt.Printf("[Middleware:Validation] ✓ User-Name validated: %s\n", username)
		}

		return next.ServeRADIUS(req)
	})
}

// Statistics middleware
func statisticsMiddleware(next server.Handler) server.Handler {
	var (
		totalRequests   int
		acceptedCount   int
		rejectedCount   int
		accountingCount int
	)

	return server.HandlerFunc(func(req *server.Request) (server.Response, error) {
		totalRequests++

		resp, err := next.ServeRADIUS(req)

		if err == nil {
			switch resp.Code() {
			case packet.CodeAccessAccept:
				acceptedCount++
			case packet.CodeAccessReject:
				rejectedCount++
			case packet.CodeAccountingResponse:
				accountingCount++
			}
		}

		fmt.Printf("[Middleware:Stats] Total: %d | Accepted: %d | Rejected: %d | Accounting: %d\n",
			totalRequests, acceptedCount, rejectedCount, accountingCount)

		return resp, err
	})
}

func main() {
	// Create server
	srv, err := server.New(server.Config{
		Handler: &advancedHandler{},
	})
	if err != nil {
		log.Fatal(err)
	}

	// Add middlewares (order matters!)
	srv.Use(auditMiddleware(os.Stdout)) // Audit logging in JSON format
	srv.Use(loggingMiddleware)          // Outermost: logs everything
	srv.Use(statisticsMiddleware)       // Tracks statistics
	srv.Use(validationMiddleware)       // Validates requests
	srv.Use(attributeListMiddleware)    // Lists attributes (innermost before handler)

	// Create UDP listener
	conn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 1812})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("=======================================================")
	fmt.Println("Advanced RADIUS Server with Middleware")
	fmt.Println("=======================================================")
	fmt.Println("Listening on :1812")
	fmt.Println("Middlewares enabled:")
	fmt.Println("  1. Audit - JSON audit logging to stdout")
	fmt.Println("  2. Logging - Logs all requests and responses")
	fmt.Println("  3. Statistics - Tracks request counts")
	fmt.Println("  4. Validation - Validates required attributes")
	fmt.Println("  5. Attribute List - Shows all request attributes")
	fmt.Println("=======================================================")

	transport := server.NewUDPTransport(conn)
	log.Fatal(srv.Serve(transport))
}
