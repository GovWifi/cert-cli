package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certcli/pki"
)

func TestViewCommandRegistered(t *testing.T) {
	found := false
	for _, command := range rootCmd.Commands() {
		if command.Name() == "view" {
			found = true
		}
	}
	if !found {
		t.Fatal("view is not registered")
	}
}

func TestViewCommandDecodesCertificate(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	notBefore := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2027, 10, 1, 23, 59, 59, 0, time.UTC)
	certPEM, err := pki.CreateSelfSignedCertificate(key, "view-me", nil, notBefore, notAfter)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "cert.pem")
	if err := os.WriteFile(path, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"view", path})
	defer rootCmd.SetArgs(nil)

	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	runErr := rootCmd.Execute()
	_ = w.Close()
	os.Stdout = old
	out, readErr := io.ReadAll(r)
	_ = r.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if runErr != nil {
		t.Fatal(runErr)
	}
	if !strings.Contains(string(out), "CN = view-me") {
		t.Fatalf("command output missing subject:\n%s", out)
	}
}
