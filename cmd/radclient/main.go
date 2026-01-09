package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/vitalvas/goradius"
)

func parseAttributes(scanner *bufio.Scanner) (map[string]interface{}, error) {
	attributes := make(map[string]interface{})

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid attribute format: %q (expected 'Name = value')", line)
		}

		name := strings.TrimSpace(parts[0])
		valueStr := strings.TrimSpace(parts[1])

		var value interface{}
		if num, err := strconv.ParseUint(valueStr, 10, 32); err == nil {
			value = uint32(num)
		} else {
			value = valueStr
		}

		attributes[name] = value
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading input: %w", err)
	}

	return attributes, nil
}

func main() {
	server := flag.String("server", "", "RADIUS server address (host:port, default port 3799)")
	action := flag.String("action", "coa", "Action: coa or disconnect")
	secret := flag.String("secret", "testing123", "Shared secret")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s -server <host[:port]> [-action <coa|disconnect>] [-secret <secret>]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nAttributes are read from stdin, one per line in format:\n")
		fmt.Fprintf(os.Stderr, "  Attribute-Name = value\n")
		fmt.Fprintf(os.Stderr, "\nExamples:\n")
		fmt.Fprintf(os.Stderr, "  echo 'User-Name = testuser' | %s -server 127.0.0.1\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  echo 'User-Name = testuser' | %s -server 127.0.0.1 -action coa -secret testing123\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  cat attrs.txt | %s -server 10.0.0.1:3799 -action disconnect -secret secret123\n", os.Args[0])
	}

	flag.Parse()

	if *server == "" {
		fmt.Fprintf(os.Stderr, "Error: -server is required\n\n")
		flag.Usage()
		os.Exit(1)
	}

	if *action != "coa" && *action != "disconnect" {
		fmt.Fprintf(os.Stderr, "Error: Invalid action %q (must be 'coa' or 'disconnect')\n\n", *action)
		flag.Usage()
		os.Exit(1)
	}

	if !strings.Contains(*server, ":") {
		*server += ":3799"
	}

	dict, err := goradius.NewDefault()
	if err != nil {
		log.Fatalf("Failed to load dictionary: %v", err)
	}

	scanner := bufio.NewScanner(os.Stdin)
	attributes, err := parseAttributes(scanner)
	if err != nil {
		log.Fatalf("Failed to parse attributes: %v", err)
	}

	if len(attributes) == 0 {
		log.Fatal("Error: No attributes provided")
	}

	cl, err := goradius.NewClient(goradius.ClientConfig{
		Addr:       *server,
		Secret:     []byte(*secret),
		Dictionary: dict,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	var resp *goradius.Packet

	switch *action {
	case "coa":
		resp, err = cl.CoA(attributes)
	case "disconnect":
		resp, err = cl.Disconnect(attributes)
	}

	if err != nil {
		log.Fatalf("Request failed: %v", err)
	}

	fmt.Printf("Received %s\n", resp.Code.String())

	respAttrs := resp.ListAttributes()
	if len(respAttrs) > 0 {
		for _, attrName := range respAttrs {
			values := resp.GetAttribute(attrName)
			for _, val := range values {
				fmt.Printf("\t%s = %s\n", attrName, val.String())
			}
		}
	}

	if resp.Code == goradius.CodeCoAACK || resp.Code == goradius.CodeDisconnectACK {
		os.Exit(0)
	}
	os.Exit(1)
}
