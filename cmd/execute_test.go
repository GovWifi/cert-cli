package cmd

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestExecute(t *testing.T) {
	if args := os.Getenv("CERTCLI_TEST_EXECUTE"); args != "" {
		os.Args = append([]string{"cert-cli"}, strings.Fields(args)...)
		Execute()
		return
	}

	t.Run("help", func(t *testing.T) {
		out, err := runExecute(t, "--help")
		if err != nil {
			t.Fatalf("help: %v\n%s", err, out)
		}
		if !strings.Contains(out, "Generate, validate, and view GovWifi CA certificates") {
			t.Fatalf("help output:\n%s", out)
		}
	})

	t.Run("unknown", func(t *testing.T) {
		out, err := runExecute(t, "not-a-command")
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
			t.Fatalf("exit err = %v, output:\n%s", err, out)
		}
		if !strings.Contains(out, "unknown command") {
			t.Fatalf("output:\n%s", out)
		}
	})
}

func runExecute(t *testing.T, args string) (string, error) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestExecute$")
	cmd.Env = append(os.Environ(), "CERTCLI_TEST_EXECUTE="+args)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
