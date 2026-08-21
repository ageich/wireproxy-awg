//go:build windows

package main

import "os/exec"

func configureDaemonProcess(cmd *exec.Cmd) {
	// Windows does not support Unix Setsid.
	// Standard handles are already redirected to os.DevNull
	// by startDaemon.
}
