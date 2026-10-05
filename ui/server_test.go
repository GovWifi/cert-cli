package ui

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHandler(t *testing.T) {
	handler, err := NewHandler()
	if err != nil {
		t.Fatal(err)
	}

	body := getOK(t, handler, "/")
	if !strings.Contains(body, "<h1>cert-cli</h1>") {
		t.Fatalf("index body:\n%s", body)
	}

	css := getOK(t, handler, "/static/style.css")
	if !strings.Contains(css, "--ink:") {
		t.Fatalf("stylesheet:\n%s", css)
	}

	rec := serve(handler, http.MethodPost, "/api/validate", strings.NewReader(""))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body)
	}
}

func TestListenAndServeRejectsNonLoopback(t *testing.T) {
	err := ListenAndServe("192.0.2.1:8080")
	if err == nil || !strings.Contains(err.Error(), "only listens on localhost") {
		t.Fatalf("got %v", err)
	}

	err = ListenAndServe(":8080")
	if err == nil || !strings.Contains(err.Error(), "only listens on localhost") {
		t.Fatalf("empty host: %v", err)
	}
}

func TestListenAndServeRejectsInvalidAddress(t *testing.T) {
	err := ListenAndServe("not-a-host")
	if err == nil || !strings.Contains(err.Error(), "invalid listen address") {
		t.Fatalf("got %v", err)
	}
}

func TestListenAndServeAcceptsLoopbackBeforeBind(t *testing.T) {
	for _, host := range []string{"127.0.0.1", "localhost", "127.0.0.2"} {
		t.Run(host, func(t *testing.T) {
			ln, err := net.Listen("tcp", net.JoinHostPort(host, "0"))
			if err != nil {
				t.Fatal(err)
			}
			defer ln.Close()

			err = ListenAndServe(ln.Addr().String())
			if err == nil {
				t.Fatal("expected a bind error")
			}
			if strings.Contains(err.Error(), "only listens on localhost") {
				t.Fatalf("loopback host was rejected: %v", err)
			}
		})
	}
}

func TestListenAndServe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	errc := make(chan error, 1)
	go func() {
		errc <- ListenAndServe(addr)
	}()

	deadline := time.Now().Add(3 * time.Second)
	var resp *http.Response
	for {
		select {
		case err := <-errc:
			t.Fatalf("server stopped: %v", err)
		default:
		}
		resp, err = http.Get("http://" + addr + "/")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("server did not accept connections: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "<h1>cert-cli</h1>") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
}

func getOK(t *testing.T, handler http.Handler, path string) string {
	t.Helper()
	rec := serve(handler, http.MethodGet, path, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d, body = %s", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func serve(handler http.Handler, method, path string, body io.Reader) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, body)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}
