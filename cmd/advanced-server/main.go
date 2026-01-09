package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/vitalvas/goradius"
)

type advancedHandler struct{}

func (h *advancedHandler) ServeSecret(req goradius.SecretRequest) (goradius.SecretResponse, error) {
	fmt.Printf("[Secret] Request from %s\n", req.RemoteAddr)

	return goradius.SecretResponse{
		Secret: []byte("testing123"),
		Metadata: map[string]interface{}{
			"client":  req.RemoteAddr.String(),
			"nastype": "generic",
		},
	}, nil
}

func (h *advancedHandler) ServeRADIUS(req *goradius.Request) (goradius.Response, error) {
	fmt.Printf("[Handler] Processing %s from %s\n", req.Code().String(), req.RemoteAddr)

	// Get user information
	if userValues := req.GetAttribute("User-Name"); len(userValues) > 0 {
		fmt.Printf("[Handler] User: %s\n", userValues[0].String())
	}

	resp := goradius.NewResponse(req)

	// Set appropriate response code based on request type
	switch req.Code() {
	case goradius.CodeAccessRequest:
		resp.SetCode(goradius.CodeAccessAccept)
	case goradius.CodeAccountingRequest:
		resp.SetCode(goradius.CodeAccountingResponse)
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
func loggingMiddleware(next goradius.Handler) goradius.Handler {
	return goradius.HandlerFunc(func(req *goradius.Request) (goradius.Response, error) {
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
func attributeListMiddleware(next goradius.Handler) goradius.Handler {
	return goradius.HandlerFunc(func(req *goradius.Request) (goradius.Response, error) {
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
func validationMiddleware(next goradius.Handler) goradius.Handler {
	return goradius.HandlerFunc(func(req *goradius.Request) (goradius.Response, error) {
		// Validate User-Name is present for Access-Request
		if req.Code() == goradius.CodeAccessRequest {
			userValues := req.GetAttribute("User-Name")
			if len(userValues) == 0 {
				fmt.Println("[Middleware:Validation] ERROR: User-Name is required")
				// Return Access-Reject
				resp := goradius.NewResponse(req)
				resp.SetCode(goradius.CodeAccessReject)
				if err := resp.SetAttribute("Reply-Message", "User-Name is required"); err != nil {
					return resp, fmt.Errorf("failed to set Reply-Message: %w", err)
				}
				return resp, nil
			}

			username := userValues[0].String()
			if len(username) == 0 {
				fmt.Println("[Middleware:Validation] ERROR: User-Name cannot be empty")
				resp := goradius.NewResponse(req)
				resp.SetCode(goradius.CodeAccessReject)
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
func statisticsMiddleware(next goradius.Handler) goradius.Handler {
	var (
		totalRequests   int
		acceptedCount   int
		rejectedCount   int
		accountingCount int
	)

	return goradius.HandlerFunc(func(req *goradius.Request) (goradius.Response, error) {
		totalRequests++

		resp, err := next.ServeRADIUS(req)

		if err == nil {
			switch resp.Code() {
			case goradius.CodeAccessAccept:
				acceptedCount++
			case goradius.CodeAccessReject:
				rejectedCount++
			case goradius.CodeAccountingResponse:
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
	srv, err := goradius.NewServer(goradius.ServerConfig{
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

	transport := goradius.NewUDPTransport(conn)
	log.Fatal(srv.Serve(transport))
}
