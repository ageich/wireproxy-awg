package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akamensky/argparse"
	"github.com/amnezia-vpn/amneziawg-go/device"
	wireproxyawg "github.com/ageich/wireproxy-awg"
	"github.com/landlock-lsm/go-landlock/landlock"
	"suah.dev/protect"
)

// an argument to denote that this process was spawned by -d
const daemonProcess = "daemon-process"

// default paths for wireproxy config file
var defaultConfigPaths = []string{
	"/etc/wireproxy/wireproxy.conf",
	os.Getenv("HOME") + "/.config/wireproxy.conf",
}

// version – переопределяется при сборке через -ldflags
var version = "1.0.26"

// ---------- Sandbox ----------

func lock(stage string) error {
	switch stage {
	case "boot":
		exePath := executablePath()

		if err := protect.Unveil("/", "r"); err != nil {
			return fmt.Errorf("unveil /: %w", err)
		}

		if err := protect.Unveil(exePath, "x"); err != nil {
			return fmt.Errorf("unveil %s: %w", exePath, err)
		}

		if err := protect.Pledge(
			"stdio rpath inet dns proc exec",
		); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}

		if err := landlock.V1.BestEffort().RestrictPaths(
			landlock.RODirs("/"),
		); err != nil {
			return fmt.Errorf("landlock: %w", err)
		}

	case "boot-daemon":
		// The daemon inherits the sandbox from the parent.
		// No additional restrictions are required here.

	case "read-config":
		if err := protect.Pledge(
			"stdio rpath inet dns",
		); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}

	case "ready":
		if err := protect.Pledge(
			"stdio inet dns",
		); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}

		net.DefaultResolver.PreferGo = true

		if err := landlock.V1.BestEffort().RestrictPaths(
			landlock.ROFiles(
				"/etc/resolv.conf",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/dev/fd",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/dev/zero",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/dev/urandom",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/etc/localtime",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/self/stat",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/self/status",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/usr/share/locale",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/self/cmdline",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/usr/share/zoneinfo",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/kernel/version",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/kernel/ngroups_max",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/kernel/cap_last_cap",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/vm/overcommit_memory",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/dev/log",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/dev/null",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/dev/full",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/proc/self/fd",
			).IgnoreIfMissing(),
		); err != nil {
			return fmt.Errorf("landlock: %w", err)
		}

	default:
		return fmt.Errorf(
			"invalid stage %s",
			stage,
		)
	}

	return nil
}

func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}

	return programPath
}

// ---------- Configuration ----------

func configFilePath() (string, bool) {
	for _, path := range defaultConfigPaths {
		if path == "" {
			continue
		}

		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}

	return "", false
}

// ---------- Network helpers ----------

func extractPort(addr string) (uint16, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf(
			"failed to extract port from %s: %w",
			addr,
			err,
		)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf(
			"failed to parse port from %s: %w",
			addr,
			err,
		)
	}

	if port < 0 || port > 65535 {
		return 0, fmt.Errorf(
			"port out of range in %s: %d",
			addr,
			port,
		)
	}

	return uint16(port), nil
}

func lockNetwork(
	sections []wireproxyawg.RoutineSpawner,
	infoAddr *string,
	pprofAddr *string,
) error {
	var rules []landlock.Rule

	// Health/info listener.
	if infoAddr != nil && *infoAddr != "" {
		port, err := extractPort(*infoAddr)
		if err != nil {
			return err
		}

		rules = append(
			rules,
			landlock.BindTCP(port),
		)
	}

	// pprof listener.
	if pprofAddr != nil && *pprofAddr != "" {
		port, err := extractPort(*pprofAddr)
		if err != nil {
			return err
		}

		rules = append(
			rules,
			landlock.BindTCP(port),
		)
	}

	for _, section := range sections {
		switch section := section.(type) {

		case *wireproxyawg.TCPServerTunnelConfig:
			// Target is the remote endpoint.
			port, err := extractPort(
				section.Target,
			)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.ConnectTCP(port),
			)

		case *wireproxyawg.HTTPConfig:
			// HTTP proxy listens locally.
			port, err := extractPort(
				section.BindAddress,
			)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.BindTCP(port),
			)

		case *wireproxyawg.TCPClientTunnelConfig:
			// IMPORTANT:
			//
			// BindAddress is a local listening socket.
			// The previous code incorrectly used ConnectTCP here.
			if section.BindAddress == nil {
				return fmt.Errorf(
					"TCP client bind address is nil",
				)
			}

			port, err := extractPort(
				section.BindAddress.String(),
			)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.BindTCP(port),
			)

			// The remote Target is connected through the WireGuard
			// userspace network stack and therefore isn't a classic
			// host TCP connect performed by the outer process.

		case *wireproxyawg.Socks5Config:
			// SOCKS5 listens locally.
			port, err := extractPort(
				section.BindAddress,
			)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.BindTCP(port),
			)
		}
	}

	if len(rules) == 0 {
		return nil
	}

	return landlock.V4.BestEffort().RestrictNet(
		rules...,
	)
}

// ---------- Memory ----------

// parseSize converts:
//
//	512KiB
//	512MiB
//	512GiB
//	512KB
//	512MB
//	512GB
//
// into bytes.
//
// If no suffix is present, the value is interpreted as bytes.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return 0, fmt.Errorf(
			"empty size string",
		)
	}

	lower := strings.ToLower(s)

	var multiplier int64 = 1

	switch {
	case strings.HasSuffix(lower, "kib"):
		multiplier = 1024
		s = s[:len(s)-3]

	case strings.HasSuffix(lower, "mib"):
		multiplier = 1024 * 1024
		s = s[:len(s)-3]

	case strings.HasSuffix(lower, "gib"):
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-3]

	case strings.HasSuffix(lower, "kb"):
		multiplier = 1000
		s = s[:len(s)-2]

	case strings.HasSuffix(lower, "mb"):
		multiplier = 1000 * 1000
		s = s[:len(s)-2]

	case strings.HasSuffix(lower, "gb"):
		multiplier = 1000 * 1000 * 1000
		s = s[:len(s)-2]
	}

	valueString := strings.TrimSpace(s)

	val, err := strconv.ParseInt(
		valueString,
		10,
		64,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid number format: %w",
			err,
		)
	}

	if val <= 0 {
		return 0, fmt.Errorf(
			"size must be positive",
		)
	}

	// Overflow protection.
	const maxInt64 = int64(^uint64(0) >> 1)

	if val > maxInt64/multiplier {
		return 0, fmt.Errorf(
			"size overflows int64",
		)
	}

	return val * multiplier, nil
}

func setMemoryLimitFromEnvAndFlags(
	memlimitFlag *int,
) (int64, error) {
	var limitBytes int64

	envLimit := os.Getenv(
		"GOMEMLIMIT",
	)

	if envLimit != "" {
		val, err := parseSize(envLimit)

		if err != nil {
			slog.Warn(
				"GOMEMLIMIT has invalid value",
				"value",
				envLimit,
				"error",
				err,
			)
		} else {
			limitBytes = val
		}
	}

	if memlimitFlag != nil &&
		*memlimitFlag > 0 {

		const maxInt64 = int64(^uint64(0) >> 1)

		flagValue := int64(*memlimitFlag)

		if flagValue > maxInt64/(1024*1024) {
			return 0, fmt.Errorf(
				"max-memory value is too large",
			)
		}

		limitBytes =
			flagValue *
				1024 *
				1024
	}

	if limitBytes > 0 {
		debug.SetMemoryLimit(
			limitBytes,
		)

		slog.Info(
			"Memory limit set",
			"bytes",
			limitBytes,
			"mb",
			limitBytes/(1024*1024),
			"gib",
			float64(limitBytes)/
				(1024 * 1024 * 1024),
		)
	} else {
		slog.Info(
			"No memory limit set",
			"use GOMEMLIMIT env or --max-memory flag",
		)
	}

	return limitBytes, nil
}

func adjustCacheSizes(
	conf *wireproxyawg.Configuration,
	limitBytes int64,
) {
	if conf == nil || limitBytes <= 0 {
		return
	}

	// Only a small fraction of the memory limit is assigned
	// to explicitly configured caches.
	total := limitBytes / 10

	dns := int(
		float64(total) *
			0.30 /
			64,
	)

	ping := int(
		float64(total) *
			0.10 /
			8,
	)

	udp := int(
		float64(total) *
			0.60 /
			1024,
	)

	const (
		minDns  = 100
		minPing = 50
		minUdp  = 100
	)

	if !conf.DnsCacheSizeSet {
		if dns < minDns {
			dns = minDns
		}

		conf.DnsCacheSize = dns

		slog.Info(
			"Auto-adjusted DnsCacheSize",
			"size",
			dns,
		)
	}

	if !conf.PingCacheSizeSet {
		if ping < minPing {
			ping = minPing
		}

		conf.PingCacheSize = ping

		slog.Info(
			"Auto-adjusted PingCacheSize",
			"size",
			ping,
		)
	}

	if !conf.UdpSessionCacheSizeSet {
		if udp < minUdp {
			udp = minUdp
		}

		conf.UdpSessionCacheSize = udp

		slog.Info(
			"Auto-adjusted UdpSessionCacheSize",
			"size",
			udp,
		)
	}
}

// ---------- Memory monitor ----------

// IMPORTANT:
//
// Do not periodically call debug.FreeOSMemory() in the hot proxy
// process. It can cause unnecessary GC latency and page reclamation.
//
// GOMEMLIMIT already provides runtime memory pressure management.
//
// We keep a lightweight periodic GC only for long-running low-memory
// VPS deployments. It does not return all pages to the kernel.
func startMemoryMonitor(
	ctx context.Context,
	interval time.Duration,
) {
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
				runtime.GC()

				slog.Debug(
					"Periodic GC completed",
				)
			}
		}
	}()
}

// ---------- Routine restart ----------

func runWithRestart(
	ctx context.Context,
	spawner wireproxyawg.RoutineSpawner,
	tun *wireproxyawg.VirtualTun,
	restartDelay time.Duration,
) {
	if spawner == nil {
		return
	}

	for {
		select {
		case <-ctx.Done():
			return

		default:
		}

		err := spawner.SpawnRoutine(
			ctx,
			tun,
		)

		if err == nil {
			return
		}

		if ctx.Err() != nil {
			return
		}

		slog.Error(
			"Routine exited with error, restarting",
			"routine",
			fmt.Sprintf("%T", spawner),
			"error",
			err,
			"delay",
			restartDelay,
		)

		timer := time.NewTimer(
			restartDelay,
		)

		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}

			return

		case <-timer.C:
		}
	}
}

// ---------- Main ----------

func main() {
	wireproxyawg.Log = slog.New(
		slog.NewTextHandler(
			os.Stderr,
			nil,
		),
	)

	// Detect daemon child BEFORE argparse.
	//
	// "daemon-process" is an internal argument and must never be
	// passed to the normal command line parser.
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
			Help: "Set maximum memory limit in megabytes (overrides GOMEMLIMIT env if set)",
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
			Help: "Enable pprof HTTP server on specified address (e.g., localhost:6060)",
		},
	)

	err := parser.Parse(
		parseArgs,
	)
	if err != nil {
		fmt.Print(
			parser.Usage(err),
		)
		os.Exit(1)
	}

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
		wireproxyawg.SetLogLevel(
			"error",
		)
	}

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

	exePath := executablePath()

	// ---------- Initial sandbox ----------

	if err := lock("boot"); err != nil {
		slog.Error(
			"Lock boot failed",
			"error",
			err,
		)
		os.Exit(1)
	}

	if isDaemonProcess {
		if err := lock(
			"boot-daemon",
		); err != nil {
			slog.Error(
				"Lock boot-daemon failed",
				"error",
				err,
			)
			os.Exit(1)
		}
	}

	// ---------- Memory ----------

	limitBytes, err :=
		setMemoryLimitFromEnvAndFlags(
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

	// ---------- Version ----------

	if *printVersion {
		fmt.Printf(
			"wireproxy, version %s\n",
			version,
		)
		return
	}

	// ---------- Config path ----------

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

	// ---------- Config read sandbox ----------

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

	// The daemon parent also needs to read the configuration
	// before spawning the child.
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

	// ---------- Parse config ----------

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

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	// ---------- Network sandbox ----------

	//
	// This MUST happen before starting pprof or any local TCP
	// listeners.
	//
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

	// ---------- Daemon ----------

	if *daemon && !isDaemonProcess {
		args := make(
			[]string,
			0,
			len(os.Args)+1,
		)

		args = append(
			args,
			daemonProcess,
		)

		// Preserve all original arguments.
		args = append(
			args,
			os.Args[1:]...,
		)

		cmd := exec.Command(
			exePath,
			args...,
		)

		// Detach standard streams from the daemon.
		devNull, err := os.OpenFile(
			os.DevNull,
			os.O_RDWR,
			0,
		)
		if err != nil {
			fmt.Fprintln(
				os.Stderr,
				err.Error(),
			)
			os.Exit(1)
		}

		cmd.Stdin = devNull
		cmd.Stdout = devNull
		cmd.Stderr = devNull

		// New process group.
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Setsid: true,
		}

		if err := cmd.Start(); err != nil {
			_ = devNull.Close()

			fmt.Fprintln(
				os.Stderr,
				err.Error(),
			)

			os.Exit(1)
		}

		_ = devNull.Close()

		return
	}

	// ---------- Daemon child output ----------

	if isDaemonProcess {
		devNull, err := os.OpenFile(
			os.DevNull,
			os.O_RDWR,
			0,
		)

		if err == nil {
			os.Stdout = devNull
			os.Stderr = devNull
		}

		*daemon = false
	}

	// Preserve stderr for device logging.
	os.Stdout = os.NewFile(
		uintptr(syscall.Stderr),
		"/dev/stderr",
	)

	// ---------- Final sandbox ----------

	logLevel := device.LogLevelVerbose

	if *silent {
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

	// ---------- Cache sizing ----------

	adjustCacheSizes(
		conf,
		limitBytes,
	)

	// ---------- WireGuard ----------

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

	// ---------- Routines ----------

	restartDelay := 15 * time.Second

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
				restartDelay,
			)
		}(spawner)
	}

	// ---------- Ping ----------

	tun.StartPingIPs()

	// ---------- pprof ----------

	var pprofServer *http.Server

	if *pprofAddr != "" {
		pprofServer = &http.Server{
			Addr: *pprofAddr,

			// net/http/pprof registers its handlers on
			// DefaultServeMux.
			Handler: http.DefaultServeMux,

			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		go func() {
			slog.Info(
				"Starting pprof server",
				"addr",
				*pprofAddr,
			)

			err := pprofServer.ListenAndServe()

			if err != nil &&
				err != http.ErrServerClosed {

				slog.Error(
					"pprof server error",
					"error",
					err,
				)
			}
		}()
	}

	// ---------- Metrics / health server ----------

	var metricsServer *http.Server

	if *info != "" {
		metricsServer = &http.Server{
			Addr: *info,
			Handler: tun,

			ReadHeaderTimeout: 5 * time.Second,
			IdleTimeout:       60 * time.Second,
		}

		go func() {
			err := metricsServer.ListenAndServe()

			if err != nil &&
				err != http.ErrServerClosed {

				slog.Error(
					"metrics server error",
					"error",
					err,
				)
			}
		}()
	}

	// ---------- Memory management ----------

	//
	// GOMEMLIMIT is the primary memory control mechanism.
	// Periodic GC is deliberately infrequent.
	//
	startMemoryMonitor(
		ctx,
		10*time.Minute,
	)

	// ---------- Reloadable routines ----------

	var reloadables []wireproxyawg.Reloadable

	for _, r := range conf.Routines {
		if rl, ok := r.(wireproxyawg.Reloadable); ok {
			reloadables = append(
				reloadables,
				rl,
			)
		}
	}

	// ---------- Signal handler ----------

	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case sig := <-sigCh:
				switch sig {

				case syscall.SIGHUP:
					slog.Info(
						"Received SIGHUP, reloading configuration...",
					)

					newConf, err :=
						wireproxyawg.ParseConfig(
							*config,
						)
					if err != nil {
						slog.Error(
							"Failed to reload config",
							"error",
							err,
						)
						continue
					}

					for _, rl := range reloadables {
						if err := rl.Reload(
							newConf,
						); err != nil {
							slog.Error(
								"Reload failed",
								"routine",
								fmt.Sprintf(
									"%T",
									rl,
								),
								"error",
								err,
							)
						}
					}

					tun.DnsCacheSize =
						newConf.DnsCacheSize

					tun.UdpSessionCacheSize =
						newConf.UdpSessionCacheSize

					tun.DnsTtl =
						time.Duration(
							newConf.DnsTtl,
						) * time.Second

					slog.Info(
						"Configuration reloaded successfully",
					)

				default:
					cancel()
					return
				}
			}
		}
	}()

	// ---------- Main wait ----------

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

	// Stop accepting new work first.
	tun.StopPingIPs()

	// Stop SOCKS5 listener if supported.
	for _, spawner := range conf.Routines {
		if s5, ok :=
			spawner.(*wireproxyawg.Socks5Config); ok {

			s5.Stop()
		}
	}

	// Shutdown health server.
	if metricsServer != nil {
		if err := metricsServer.Shutdown(
			shutdownCtx,
		); err != nil {
			slog.Error(
				"HTTP server shutdown error",
				"error",
				err,
			)
		}
	}

	// Shutdown pprof.
	if pprofServer != nil {
		if err := pprofServer.Shutdown(
			shutdownCtx,
		); err != nil {
			slog.Error(
				"pprof server shutdown error",
				"error",
				err,
			)
		}
	}

	// Wait for routine managers.
	routinesDone := make(chan struct{})

	go func() {
		routineWG.Wait()
		close(routinesDone)
	}()

	select {
	case <-routinesDone:
		slog.Debug(
			"All routine goroutines stopped",
		)

	case <-shutdownCtx.Done():
		slog.Warn(
			"Routine shutdown timed out",
		)
	}

	// Close WireGuard device last.
	if tun.Dev != nil {
		tun.Dev.Close()
	}

	slog.Info(
		"Shutdown complete",
	)
}
