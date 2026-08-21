package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/device"
	wireproxyawg "github.com/ageich/wireproxy-awg"
)

const daemonProcess = "daemon-process"

// version – переопределяется при сборке через -ldflags
var version = "1.0.26"

func main() {
	wireproxyawg.Log = slog.New(
		slog.NewTextHandler(
			os.Stderr,
			nil,
		),
	)

	// ------------------------------------------------------------
	// Arguments
	// ------------------------------------------------------------

	args, err := parseCommandLine()
	if err != nil {
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Initial sandbox
	// ------------------------------------------------------------

	if err := lock("boot"); err != nil {
		slog.Error(
			"Lock boot failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	if args.isDaemonProcess {
		if err := lock("boot-daemon"); err != nil {
			slog.Error(
				"Lock boot-daemon failed",
				"error",
				err,
			)
			os.Exit(1)
		}
	}

	// ------------------------------------------------------------
	// Memory
	// ------------------------------------------------------------

	limitBytes, err := setMemoryLimitFromEnvAndFlags(
		args.memlimit,
	)
	if err != nil {
		slog.Error(
			"Failed to configure memory limit",
			"error",
			err,
		)
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Version
	// ------------------------------------------------------------

	if args.printVersion {
		fmt.Printf(
			"wireproxy, version %s\n",
			version,
		)
		return
	}

	// ------------------------------------------------------------
	// Config path
	// ------------------------------------------------------------

	if args.config == "" {
		if path, exists := configFilePath(); exists {
			args.config = path
		} else {
			fmt.Println(
				"configuration path is required",
			)
			os.Exit(1)
		}
	}

	// ------------------------------------------------------------
	// Config sandbox
	// ------------------------------------------------------------

	if !args.isDaemonProcess || args.daemon {
		if err := lock("read-config"); err != nil {
			slog.Error(
				"Lock read-config failed",
				"error",
				err,
			)
			os.Exit(1)
		}
	}

	// ------------------------------------------------------------
	// Parse config
	// ------------------------------------------------------------

	conf, err := wireproxyawg.ParseConfig(
		args.config,
	)
	if err != nil {
		slog.Error(
			"Parse config failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	if args.configTest {
		fmt.Println("Config OK")
		return
	}

	// ------------------------------------------------------------
	// Network sandbox
	// ------------------------------------------------------------

	if err := lockNetwork(
		conf.Routines,
		args.info,
		args.pprofAddr,
	); err != nil {
		slog.Error(
			"Lock network failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Daemon
	// ------------------------------------------------------------

	if args.daemon && !args.isDaemonProcess {
		if err := daemonize(); err != nil {
			slog.Error(
				"Failed to start daemon",
				"error",
				err,
			)
			os.Exit(1)
		}

		return
	}

	// ------------------------------------------------------------
	// Daemon child output
	// ------------------------------------------------------------

	if args.isDaemonProcess {
		redirectDaemonOutput()
		args.daemon = false
	}

	// Preserve stderr for device logging.
	os.Stdout = os.NewFile(
		uintptr(syscall.Stderr),
		"/dev/stderr",
	)

	// ------------------------------------------------------------
	// Final sandbox
	// ------------------------------------------------------------

	logLevel := device.LogLevelVerbose

	if args.silent {
		logLevel = device.LogLevelSilent
	}

	if err := lock("ready"); err != nil {
		slog.Error(
			"Lock ready failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Cache sizing
	// ------------------------------------------------------------

	adjustCacheSizes(
		conf,
		limitBytes,
	)

	// ------------------------------------------------------------
	// WireGuard
	// ------------------------------------------------------------

	tun, err := wireproxyawg.StartWireguard(
		conf.Device,
		logLevel,
		conf.PingCacheSize,
	)
	if err != nil {
		slog.Error(
			"Start wireguard failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	tun.DnsCacheSize =
		conf.DnsCacheSize

	tun.UdpSessionCacheSize =
		conf.UdpSessionCacheSize

	tun.DnsTtl =
		time.Duration(
			conf.DnsTtl,
		) * time.Second

	// ------------------------------------------------------------
	// Context / signals
	// ------------------------------------------------------------

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	sigCh := make(
		chan os.Signal,
		1,
	)

	signal.Notify(
		sigCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)

	// ------------------------------------------------------------
	// Routines
	// ------------------------------------------------------------

	restartDelay := 15 * time.Second

	var routineWG sync.WaitGroup

	startRoutines(
		ctx,
		conf.Routines,
		tun,
		restartDelay,
		&routineWG,
	)

	// ------------------------------------------------------------
	// Ping
	// ------------------------------------------------------------

	tun.StartPingIPs()

	// ------------------------------------------------------------
	// HTTP servers
	// ------------------------------------------------------------

	pprofServer := startPprofServer(
		args.pprofAddr,
	)

	metricsServer := startMetricsServer(
		args.info,
		tun,
	)

	// ------------------------------------------------------------
	// Memory monitor
	// ------------------------------------------------------------

	startMemoryMonitor(
		ctx,
		10*time.Minute,
	)

	// ------------------------------------------------------------
	// Reloadable routines
	// ------------------------------------------------------------

	reloadables := collectReloadables(
		conf.Routines,
	)

	// ------------------------------------------------------------
	// Signal handler
	// ------------------------------------------------------------

	startSignalHandler(
		ctx,
		cancel,
		sigCh,
		args.config,
		reloadables,
		tun,
	)

	// ------------------------------------------------------------
	// Wait
	// ------------------------------------------------------------

	<-ctx.Done()

	slog.Info(
		"Shutting down gracefully...",
	)

	shutdownCtx, shutdownCancel :=
		context.WithTimeout(
			context.Background(),
			5*time.Second,
		)
	defer shutdownCancel()

	// ------------------------------------------------------------
	// Shutdown
	// ------------------------------------------------------------

	tun.StopPingIPs()

	stopSocks5Routines(
		conf.Routines,
	)

	shutdownHTTPServer(
		shutdownCtx,
		metricsServer,
		"metrics",
	)

	shutdownHTTPServer(
		shutdownCtx,
		pprofServer,
		"pprof",
	)

	waitRoutines(
		shutdownCtx,
		&routineWG,
	)

	// WireGuard device is closed last.
	if tun.Dev != nil {
		tun.Dev.Close()
	}

	slog.Info(
		"Shutdown complete",
	)

	_ = http.ErrServerClosed
}
