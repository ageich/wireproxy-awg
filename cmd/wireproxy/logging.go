package main

import (
	"log/slog"
	"os"

	wireproxyawg "github.com/ageich/wireproxy-awg"
)

func initLogging() {
	wireproxyawg.Log = slog.New(
		slog.NewTextHandler(
			os.Stderr,
			nil,
		),
	)
}
