package main

import (
	"context"
	"log/slog"
	"net/http"
	"sync"

	wireproxyawg "github.com/ageich/wireproxy-awg"
)

func gracefulShutdown(
	shutdownCtx context.Context,
	tun *wireproxyawg.VirtualTun,
	routines []wireproxyawg.RoutineSpawner,
	routineWG *sync.WaitGroup,
	metricsServer *http.Server,
	pprofServer *http.Server,
) {
	// Stop accepting new ping work.
	if tun != nil {
		tun.StopPingIPs()
	}

	// Stop SOCKS5 listeners.
	for _, routine := range routines {
		s5, ok := routine.(*wireproxyawg.Socks5Config)
		if !ok || s5 == nil {
			continue
		}

		s5.Stop()
	}

	// Shutdown health/info server.
	if metricsServer != nil {
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			slog.Error(
				"HTTP server shutdown error",
				"server",
				"metrics",
				"error",
				err,
			)
		}
	}

	// Shutdown pprof.
	if pprofServer != nil {
		if err := pprofServer.Shutdown(shutdownCtx); err != nil {
			slog.Error(
				"HTTP server shutdown error",
				"server",
				"pprof",
				"error",
				err,
			)
		}
	}

	// Wait for routine goroutines.
	if routineWG != nil {
		done := make(chan struct{})

		go func() {
			routineWG.Wait()
			close(done)
		}()

		select {
		case <-done:
			slog.Debug(
				"All routine goroutines stopped",
			)

		case <-shutdownCtx.Done():
			slog.Warn(
				"Routine shutdown timed out",
			)
		}
	}

	// Close WireGuard device last.
	if tun != nil && tun.Dev != nil {
		tun.Dev.Close()
	}

	slog.Info("Shutdown complete")
}
