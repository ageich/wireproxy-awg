package main

import (
	"os"
	"os/exec"
	"syscall"
)

func daemonize() error {
	exePath := executablePath()

	args := make(
		[]string,
		0,
		len(os.Args)+1,
	)

	args = append(
		args,
		daemonProcess,
	)

	args = append(
		args,
		os.Args[1:]...,
	)

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
		return err
	}

	cmd.Stdin = devNull
	cmd.Stdout = devNull
	cmd.Stderr = devNull

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}

	if err := cmd.Start(); err != nil {
		_ = devNull.Close()
		return err
	}

	_ = devNull.Close()

	return nil
}

func redirectDaemonOutput() {
	devNull, err := os.OpenFile(
		os.DevNull,
		os.O_RDWR,
		0,
	)

	if err == nil {
		os.Stdout = devNull
		os.Stderr = devNull
	}
}
