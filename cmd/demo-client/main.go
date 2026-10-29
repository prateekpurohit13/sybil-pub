// Command demo-client performs one HTTPS request with Go's default TLS stack.
// It exists so the demo can generate a Go crypto/tls ClientHello.
package main

import (
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		os.Exit(2)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	response, err := client.Get(os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	response.Body.Close()
}
