package cmd

import (
	"fmt"
	"os/exec"
	"runtime"
	"time"

	"certcli/ui"

	"github.com/spf13/cobra"
)

var uiCmd = &cobra.Command{
	Use:   "ui",
	Short: "Start the embedded local web UI",
	RunE: func(cmd *cobra.Command, args []string) error {
		addrFlag, err := cmd.Flags().GetString("addr")
		if err != nil {
			return err
		}
		port, err := cmd.Flags().GetInt("port")
		if err != nil {
			return err
		}
		if port < 1 || port > 65535 {
			return fmt.Errorf("port must be between 1 and 65535")
		}

		listen := fmt.Sprintf("%s:%d", addrFlag, port)
		url := fmt.Sprintf("http://%s", listen)

		go func() {
			time.Sleep(200 * time.Millisecond)
			_ = openBrowser(url)
		}()

		return ui.ListenAndServe(listen)
	},
}

func init() {
	uiCmd.Flags().String("addr", "127.0.0.1", "listen address (localhost only)")
	uiCmd.Flags().Int("port", 30800, "listen port")
	rootCmd.AddCommand(uiCmd)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform")
	}
	return cmd.Start()
}
