package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	wireproxyawg "github.com/ageich/wireproxy-awg"
	"github.com/akamensky/argparse"
	"github.com/amnezia-vpn/amneziawg-go/device"
)

var version = "1.0.26"

func main() {
	wireproxyawg.Log = slog.New(
		slog.NewTextHandler(
			os.Stderr,
			nil,
		),
	)

	// Detect daemon child before argparse.
	isDaemonProcess :=
		len(os.Args) > 1 &&
			os.Args[1] == daemonProcess

	parseArgs := os.Args

	if isDaemonProcess {
		parseArgs = make(
			[]string,
			0,
			len(os.Args)-1,
		)

		parseArgs = append(
			parseArgs,
			os.Args[0],
		)

		parseArgs = append(
			parseArgs,
			os.Args[2:]...,
		)
	}

	// ------------------------------------------------------------
	// Arguments
	// ------------------------------------------------------------

	parser := argparse.NewParser(
		"wireproxy",
		"Userspace wireguard client for proxying",
	)

	config := parser.String(
		"c",
		"config",
		&argparse.Options{
			Help: "Path of configuration file",
		},
	)

	silent := parser.Flag(
		"s",
		"silent",
		&argparse.Options{
			Help: "Silent mode",
		},
	)

	daemon := parser.Flag(
		"d",
		"daemon",
		&argparse.Options{
			Help: "Make wireproxy run in background",
		},
	)

	info := parser.String(
		"i",
		"info",
		&argparse.Options{
			Help: "Specify the address and port for exposing health status",
		},
	)

	printVersion := parser.Flag(
		"v",
		"version",
		&argparse.Options{
			Help: "Print version",
		},
	)

	configTest := parser.Flag(
		"n",
		"configtest",
		&argparse.Options{
			Help: "Configtest mode. Only check the configuration file for validity.",
		},
	)

	memlimit := parser.Int(
		"",
		"max-memory",
		&argparse.Options{
			Help: "Set maximum memory limit in megabytes",
		},
	)

	logLevelFlag := parser.String(
		"",
		"log-level",
		&argparse.Options{
			Help:    "Log level (debug, info, warn, error)",
			Default: "info",
		},
	)

	pprofAddr := parser.String(
		"",
		"pprof",
		&argparse.Options{
			Help: "Enable pprof HTTP server",
		},
	)

	if err := parser.Parse(parseArgs); err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Logging
	// ------------------------------------------------------------

	if err := wireproxyawg.SetLogLevel(
		*logLevelFlag,
	); err != nil {
		fmt.Fprintf(
			os.Stderr,
			"Invalid log level: %v\n",
			err,
		)
		os.Exit(1)
	}

	if *silent {
		wireproxyawg.SetLogLevel("error")
	}

	// ------------------------------------------------------------
	// Context / signals
	// ------------------------------------------------------------

	ctx, cancel := context.WithCancel(
		context.Background(),
	)
	defer cancel()

	sigCh := make(chan os.Signal, 1)

	signal.Notify(
		sigCh,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT,
		syscall.SIGHUP,
	)

	// ------------------------------------------------------------
	// Executable
	// ------------------------------------------------------------

	exePath := executablePath()

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

	if isDaemonProcess {
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
		memlimit,
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

	if *printVersion {
		fmt.Printf(
			"wireproxy, version %s\n",
			version,
		)
		return
	}

	// ------------------------------------------------------------
	// Configuration path
	// ------------------------------------------------------------

	if *config == "" {
		if path, exists := configFilePath(); exists {
			*config = path
		} else {
			fmt.Println(
				"configuration path is required",
			)
			os.Exit(1)
		}
	}

	// ------------------------------------------------------------
	// Config read sandbox
	// ------------------------------------------------------------

	if !isDaemonProcess && !*daemon {
		if err := lock("read-config"); err != nil {
			slog.Error(
				"Lock read-config failed",
				"error",
				err,
			)
			os.Exit(1)
		}
	}

	if *daemon && !isDaemonProcess {
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
	// Parse configuration
	// ------------------------------------------------------------

	conf, err := wireproxyawg.ParseConfig(
		*config,
	)
	if err != nil {
		slog.Error(
			"Parse config failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	// ------------------------------------------------------------
	// Config test
	// ------------------------------------------------------------

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	// ------------------------------------------------------------
	// Network sandbox
	// ------------------------------------------------------------

	if err := lockNetwork(
		conf.Routines,
		info,
		pprofAddr,
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

	if *daemon && !isDaemonProcess {
		if err := startDaemon(
			exePath,
			os.Args,
		); err != nil {
			fmt.Fprintln(
				os.Stderr,
				err,
			)
			os.Exit(1)
		}

		return
	}

	// ------------------------------------------------------------
	// Daemon child output
	// ------------------------------------------------------------

	if isDaemonProcess {
		redirectDaemonOutput()
		*daemon = false
	}

	// ------------------------------------------------------------
	// WireGuard log level
	// ------------------------------------------------------------

	logLevel := device.LogLevelVerbose

	if *silent {
		logLevel = device.LogLevelSilent
	}

	// ------------------------------------------------------------
	// Final sandbox
	// ------------------------------------------------------------

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
	// Start WireGuard
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
	// Routines
	// ------------------------------------------------------------

	var routineWG sync.WaitGroup

	for _, spawner := range conf.Routines {
		if spawner == nil {
			continue
		}

		routineWG.Add(1)

		go func(
			spawner wireproxyawg.RoutineSpawner,
		) {
			defer routineWG.Done()

			runWithRestart(
				ctx,
				spawner,
				tun,
				15*time.Second,
			)
		}(spawner)
	}

	// ------------------------------------------------------------
	// Ping
	// ------------------------------------------------------------

	tun.StartPingIPs()

	// ------------------------------------------------------------
	// pprof
	// ------------------------------------------------------------

	var pprofServer *http.Server

	if *pprofAddr != "" {
		pprofServer = startPprof(
			*pprofAddr,
		)
	}

	// ------------------------------------------------------------
	// Metrics / health
	// ------------------------------------------------------------

	var metricsServer *http.Server

	if *info != "" {
		metricsServer = startMetrics(
			*info,
			tun,
		)
	}

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

	go handleSignals(
		ctx,
		cancel,
		sigCh,
		*config,
		tun,
		reloadables,
	)

	// Keep runtime configuration explicit.
	_ = runtime.GOMAXPROCS(0)

	// ------------------------------------------------------------
	// Wait
	// ------------------------------------------------------------

	<-ctx.Done()

	// ------------------------------------------------------------
	// Graceful shutdown
	// ------------------------------------------------------------

	shutdownCtx, shutdownCancel := context.WithTimeout(
		context.Background(),
		5*time.Second,
	)
	defer shutdownCancel()

	gracefulShutdown(
		shutdownCtx,
		tun,
		conf.Routines,
		&routineWG,
		pprofServer,
		metricsServer,
	)
}
