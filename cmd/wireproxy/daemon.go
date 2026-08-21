package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

const daemonProcess = "daemon-process"

// startDaemon starts a detached child process.
func startDaemon(
	exePath string,
	args []string,
) error {
	cmd := exec.Command(
		exePath,
		args...,
	)

	devNull, err := os.OpenFile(
		os.DevNull,
		os.O_RDWR,
		0,
	)
	if err != nil {
		return fmt.Errorf(
			"open %s: %w",
			os.DevNull,
			err,
		)
	}

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		_ = devNull.Close()

		return fmt.Errorf(
			"start daemon: %w",
			err,
		)
	}

	_ = devNull.Close()

	return nil
}

// daemonize is kept as a small wrapper for compatibility.
func daemonize(
	exePath string,
	args []string,
) error {
	return startDaemon(
		exePath,
		args,
	)
}

// redirectDaemonOutput disconnects stdout/stderr from the terminal.
func redirectDaemonOutput() {
	devNull, err := os.OpenFile(
		os.DevNull,
		os.O_RDWR,
		0,
	)
	if err != nil {
		return
	}

	os.Stdout = devNull
	os.Stderr = devNull
}

// daemonArguments removes the internal daemon marker from argv.
func daemonArguments(
	isDaemon bool,
) []string {
	if !isDaemon {
		return os.Args
	}

	args := make(
		[]string,
		0,
		len(os.Args)-1,
	)

	args = append(
		args,
		os.Args[0],
	)

	args = append(
		args,
		os.Args[2:]...,
	)

	return args
}
