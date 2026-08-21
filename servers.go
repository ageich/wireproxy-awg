package main

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	wireproxyawg "github.com/ageich/wireproxy-awg"

	_ "net/http/pprof"
)

func startPprofServer(
	addr string,
) *http.Server {
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

func startMetricsServer(
	addr string,
	tun *wireproxyawg.VirtualTun,
) *http.Server {
	if addr == "" {
		return nil
	}

	server := &http.Server{
		Addr: addr,

		Handler: tun,

		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	go func() {
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

func shutdownHTTPServer(
	ctx context.Context,
	server *http.Server,
	name string,
) {
	if server == nil {
		return
	}

	if err := server.Shutdown(ctx); err != nil {
		slog.Error(
			"HTTP server shutdown error",
			"server",
			name,
			"error",
			err,
		)
	}
}
