package ui

import (
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"

	"certcli/ui/handlers"
)

func NewHandler() (http.Handler, error) {
	staticRoot, err := fs.Sub(staticFS, "static")
	if err != nil {
		return nil, err
	}
	return handlers.New(staticRoot), nil
}

func ListenAndServe(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	if !isLoopbackHost(host) {
		return fmt.Errorf("ui only listens on localhost (got %q)", host)
	}

	handler, err := NewHandler()
	if err != nil {
		return err
	}

	fmt.Printf("cert-cli ui listening on http://%s\n", addr)
	return http.ListenAndServe(addr, handler)
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSpace(strings.ToLower(host))
	switch host {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
