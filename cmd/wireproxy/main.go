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
var version = "1.0.23-test"

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
		if err := protect.Pledge("stdio rpath inet dns proc exec"); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}
		if err := landlock.V1.BestEffort().RestrictPaths(
			landlock.RODirs("/"),
		); err != nil {
			return fmt.Errorf("landlock: %w", err)
		}
	case "boot-daemon":
		// nothing
	case "read-config":
		if err := protect.Pledge("stdio rpath inet dns"); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}
	case "ready":
		if err := protect.Pledge("stdio inet dns"); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}
		net.DefaultResolver.PreferGo = true
		if err := landlock.V1.BestEffort().RestrictPaths(
			landlock.ROFiles("/etc/resolv.conf").IgnoreIfMissing(),
			landlock.ROFiles("/dev/fd").IgnoreIfMissing(),
			landlock.ROFiles("/dev/zero").IgnoreIfMissing(),
			landlock.ROFiles("/dev/urandom").IgnoreIfMissing(),
			landlock.ROFiles("/etc/localtime").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/stat").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/status").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/locale").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/cmdline").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/zoneinfo").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/version").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/ngroups_max").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/cap_last_cap").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/vm/overcommit_memory").IgnoreIfMissing(),
			landlock.RWFiles("/dev/log").IgnoreIfMissing(),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
			landlock.RWFiles("/dev/full").IgnoreIfMissing(),
			landlock.RWFiles("/proc/self/fd").IgnoreIfMissing(),
		); err != nil {
			return fmt.Errorf("landlock: %w", err)
		}
	default:
		return fmt.Errorf("invalid stage %s", stage)
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

func configFilePath() (string, bool) {
	for _, path := range defaultConfigPaths {
		if _, err := os.Stat(path); err == nil {
			return path, true
		}
	}
	return "", false
}

func extractPort(addr string) (uint16, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("failed to extract port from %s: %w", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf("failed to parse port from %s: %w", addr, err)
	}
	return uint16(port), nil
}

func lockNetwork(sections []wireproxyawg.RoutineSpawner, infoAddr *string, pprofAddr *string) error {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		port, err := extractPort(*infoAddr)
		if err != nil {
			return err
		}
		rules = append(rules, landlock.BindTCP(port))
	}
	if pprofAddr != nil && *pprofAddr != "" {
		port, err := extractPort(*pprofAddr)
		if err != nil {
			return err
		}
		rules = append(rules, landlock.BindTCP(port))
	}
	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxyawg.TCPServerTunnelConfig:
			port, err := extractPort(section.Target)
			if err != nil {
				return err
			}
			rules = append(rules, landlock.ConnectTCP(port))
		case *wireproxyawg.HTTPConfig:
			port, err := extractPort(section.BindAddress)
			if err != nil {
				return err
			}
			rules = append(rules, landlock.BindTCP(port))
		case *wireproxyawg.TCPClientTunnelConfig:
			port, err := extractPort(section.BindAddress.String())
			if err != nil {
				return err
			}
			rules = append(rules, landlock.ConnectTCP(port))
		case *wireproxyawg.Socks5Config:
			port, err := extractPort(section.BindAddress)
			if err != nil {
				return err
			}
			rules = append(rules, landlock.BindTCP(port))
		}
	}
	return landlock.V4.BestEffort().RestrictNet(rules...)
}

// parseSize преобразует строку с суффиксом (KiB, MiB, GiB, KB, MB, GB) в байты.
// Регистронезависима: поддерживает "512MiB", "512mib", "512MIB" и т.д.
// Если суффикс отсутствует, интерпретирует как число в байтах.
func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty size string")
	}
	var multiplier int64 = 1
	lower := strings.ToLower(s)
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
	val, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid number format: %w", err)
	}
	return val * multiplier, nil
}

func setMemoryLimitFromEnvAndFlags(memlimitFlag *int) (int64, error) {
	envLimit := os.Getenv("GOMEMLIMIT")
	var limitBytes int64 = 0
	if envLimit != "" {
		if val, err := parseSize(envLimit); err == nil && val > 0 {
			limitBytes = val
		} else {
			slog.Warn("GOMEMLIMIT environment variable has invalid value", "value", envLimit)
		}
	}
	if memlimitFlag != nil && *memlimitFlag > 0 {
		flagBytes := int64(*memlimitFlag) * 1024 * 1024
		limitBytes = flagBytes
	}
	if limitBytes > 0 {
		debug.SetMemoryLimit(limitBytes)
		slog.Info("Memory limit set", "bytes", limitBytes, "mb", limitBytes/(1024*1024), "gib", float64(limitBytes)/(1024*1024*1024))
	} else {
		slog.Info("No memory limit set (use GOMEMLIMIT env or --max-memory flag)")
	}
	return limitBytes, nil
}

func adjustCacheSizes(conf *wireproxyawg.Configuration, limitBytes int64) {
	if limitBytes <= 0 {
		return
	}
	total := limitBytes / 10
	dns := int(float64(total) * 0.30 / 64)
	ping := int(float64(total) * 0.10 / 8)
	udp := int(float64(total) * 0.60 / 1024)
	const minDns = 100
	const minPing = 50
	const minUdp = 100
	if !conf.DnsCacheSizeSet {
		if dns < minDns {
			dns = minDns
		}
		conf.DnsCacheSize = dns
		slog.Info("Auto-adjusted DnsCacheSize", "size", dns)
	}
	if !conf.PingCacheSizeSet {
		if ping < minPing {
			ping = minPing
		}
		conf.PingCacheSize = ping
		slog.Info("Auto-adjusted PingCacheSize", "size", ping)
	}
	if !conf.UdpSessionCacheSizeSet {
		if udp < minUdp {
			udp = minUdp
		}
		conf.UdpSessionCacheSize = udp
		slog.Info("Auto-adjusted UdpSessionCacheSize", "size", udp)
	}
}

func startMemoryMonitor(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for {
			select {
			case <-ctx.Done():
				ticker.Stop()
				return
			case <-ticker.C:
				runtime.GC()
				debug.FreeOSMemory()
				slog.Debug("Memory GC and OS memory release triggered")
			}
		}
	}()
}

func runWithRestart(ctx context.Context, spawner wireproxyawg.RoutineSpawner, tun *wireproxyawg.VirtualTun, restartDelay time.Duration) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			err := spawner.SpawnRoutine(ctx, tun)
			if err != nil {
				slog.Error("Routine exited with error, restarting", "routine", fmt.Sprintf("%T", spawner), "error", err, "delay", restartDelay)
				time.Sleep(restartDelay)
			} else {
				return
			}
		}
	}
}

func main() {
	wireproxyawg.Log = slog.New(slog.NewTextHandler(os.Stderr, nil))

	parser := argparse.NewParser("wireproxy", "Userspace wireguard client for proxying")
	config := parser.String("c", "config", &argparse.Options{Help: "Path of configuration file"})
	silent := parser.Flag("s", "silent", &argparse.Options{Help: "Silent mode"})
	daemon := parser.Flag("d", "daemon", &argparse.Options{Help: "Make wireproxy run in background"})
	info := parser.String("i", "info", &argparse.Options{Help: "Specify the address and port for exposing health status"})
	printVerison := parser.Flag("v", "version", &argparse.Options{Help: "Print version"})
	configTest := parser.Flag("n", "configtest", &argparse.Options{Help: "Configtest mode. Only check the configuration file for validity."})
	memlimit := parser.Int("", "max-memory", &argparse.Options{Help: "Set maximum memory limit in megabytes (overrides GOMEMLIMIT env if set)"})
	logLevelFlag := parser.String("", "log-level", &argparse.Options{Help: "Log level (debug, info, warn, error)", Default: "info"})
	pprofAddr := parser.String("", "pprof", &argparse.Options{Help: "Enable pprof HTTP server on specified address (e.g., localhost:6060)"})

	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

	if err := wireproxyawg.SetLogLevel(*logLevelFlag); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid log level: %v\n", err)
		os.Exit(1)
	}
	if *silent {
		wireproxyawg.SetLogLevel("error")
	}

	if *pprofAddr != "" {
		go func() {
			slog.Info("Starting pprof server", "addr", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				slog.Error("pprof server error", "error", err)
			}
		}()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	exePath := executablePath()
	if err := lock("boot"); err != nil {
		slog.Error("Lock boot failed", "error", err)
		os.Exit(1)
	}

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		if err := lock("boot-daemon"); err != nil {
			slog.Error("Lock boot-daemon failed", "error", err)
			os.Exit(1)
		}
		args = []string{args[0]}
		args = append(args, os.Args[2:]...)
	}

	limitBytes, _ := setMemoryLimitFromEnvAndFlags(memlimit)

	if *printVerison {
		fmt.Printf("wireproxy, version %s\n", version)
		return
	}

	if *config == "" {
		if path, exists := configFilePath(); exists {
			*config = path
		} else {
			fmt.Println("configuration path is required")
			os.Exit(1)
		}
	}

	if !*daemon {
		if err := lock("read-config"); err != nil {
			slog.Error("Lock read-config failed", "error", err)
			os.Exit(1)
		}
	}

	conf, err := wireproxyawg.ParseConfig(*config)
	if err != nil {
		slog.Error("Parse config failed", "error", err)
		os.Exit(1)
	}

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	if err := lockNetwork(conf.Routines, info, pprofAddr); err != nil {
		slog.Error("Lock network failed", "error", err)
		os.Exit(1)
	}

	if isDaemonProcess {
		os.Stdout, _ = os.Open(os.DevNull)
		os.Stderr, _ = os.Open(os.DevNull)
		*daemon = false
	}

	if *daemon {
		args[0] = daemonProcess
		cmd := exec.Command(exePath, args...)
		err = cmd.Start()
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		return
	}

	os.Stdout = os.NewFile(uintptr(syscall.Stderr), "/dev/stderr")
	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	if err := lock("ready"); err != nil {
		slog.Error("Lock ready failed", "error", err)
		os.Exit(1)
	}

	adjustCacheSizes(conf, limitBytes)

	tun, err := wireproxyawg.StartWireguard(conf.Device, logLevel, conf.PingCacheSize)
	if err != nil {
		slog.Error("Start wireguard failed", "error", err)
		os.Exit(1)
	}
	tun.DnsCacheSize = conf.DnsCacheSize
	tun.UdpSessionCacheSize = conf.UdpSessionCacheSize
	tun.DnsTtl = time.Duration(conf.DnsTtl) * time.Second

	restartDelay := 15 * time.Second
	for _, spawner := range conf.Routines {
		go runWithRestart(ctx, spawner, tun, restartDelay)
	}

	tun.StartPingIPs()

	var metricsServer *http.Server
	if *info != "" {
		metricsServer = &http.Server{
			Addr:    *info,
			Handler: tun,
		}
		go func() {
			if err := metricsServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("metrics server error", "error", err)
			}
		}()
	}

	startMemoryMonitor(ctx, 5*time.Minute)

	var reloadables []wireproxyawg.Reloadable
	for _, r := range conf.Routines {
		if rl, ok := r.(wireproxyawg.Reloadable); ok {
			reloadables = append(reloadables, rl)
		}
	}

	go func() {
		for sig := range sigCh {
			switch sig {
			case syscall.SIGHUP:
				slog.Info("Received SIGHUP, reloading configuration...")
				newConf, err := wireproxyawg.ParseConfig(*config)
				if err != nil {
					slog.Error("Failed to reload config", "error", err)
					continue
				}
				for _, rl := range reloadables {
					if err := rl.Reload(newConf); err != nil {
						slog.Error("Reload failed", "routine", fmt.Sprintf("%T", rl), "error", err)
					}
				}
				tun.DnsCacheSize = newConf.DnsCacheSize
				tun.UdpSessionCacheSize = newConf.UdpSessionCacheSize
				tun.DnsTtl = time.Duration(newConf.DnsTtl) * time.Second
				slog.Info("Configuration reloaded successfully")
			default:
				cancel()
				return
			}
		}
	}()

	<-ctx.Done()
	slog.Info("Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	tun.StopPingIPs()
	for _, spawner := range conf.Routines {
		if s5, ok := spawner.(*wireproxyawg.Socks5Config); ok {
			s5.Stop()
		}
	}
	if metricsServer != nil {
		if err := metricsServer.Shutdown(shutdownCtx); err != nil {
			slog.Error("HTTP server shutdown error", "error", err)
		}
	}
	if tun.Dev != nil {
		tun.Dev.Close()
	}
	<-shutdownCtx.Done()
	slog.Info("Shutdown complete")
}
