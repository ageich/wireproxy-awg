package main

import (
	"log/slog"
	"net/http"
	"time"

	_ "net/http/pprof"

	wireproxyawg "github.com/ageich/wireproxy-awg"
)

func startPprof(addr string) *http.Server {
	if addr == "" {
		return nil
	}

	server := &http.Server{
		Addr: addr,

		Handler: http.DefaultServeMux,

		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info(
			"Starting pprof server",
			"addr",
			addr,
		)

		err := server.ListenAndServe()

		if err != nil &&
			err != http.ErrServerClosed {

			slog.Error(
				"pprof server error",
				"error",
				err,
			)
		}
	}()

	return server
}

func startMetrics(
	addr string,
	tun *wireproxyawg.VirtualTun,
) *http.Server {
	if addr == "" || tun == nil {
		return nil
	}

	server := &http.Server{
		Addr:    addr,
		Handler: tun,

		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
		slog.Info(
			"Starting metrics server",
			"addr",
			addr,
		)

		err := server.ListenAndServe()

		if err != nil &&
			err != http.ErrServerClosed {

			slog.Error(
				"metrics server error",
				"error",
				err,
			)
		}
	}()

	return server
}
