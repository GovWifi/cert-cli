package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestMainHelp(t *testing.T) {
	if os.Getenv("CERTCLI_TEST_MAIN") == "1" {
		os.Args = []string{"cert-cli", "--help"}
		main()
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainHelp$")
	cmd.Env = append(os.Environ(), "CERTCLI_TEST_MAIN=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("certcli: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Generate, validate, and view GovWifi CA certificates") {
		t.Fatalf("help output:\n%s", out)
	}
}
