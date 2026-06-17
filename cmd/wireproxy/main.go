package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
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

var version = "1.0.15-dev"

// lock возвращает ошибку вместо паники
func lock(stage string) error {
	switch stage {
	case "boot":
		exePath := executablePath()
		// OpenBSD
		if err := protect.Unveil("/", "r"); err != nil {
			return fmt.Errorf("unveil /: %w", err)
		}
		if err := protect.Unveil(exePath, "x"); err != nil {
			return fmt.Errorf("unveil %s: %w", exePath, err)
		}
		if err := protect.Pledge("stdio rpath inet dns proc exec"); err != nil {
			return fmt.Errorf("pledge: %w", err)
		}
		// Linux
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

func extractPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}
	return uint16(port)
}

func lockNetwork(sections []wireproxyawg.RoutineSpawner, infoAddr *string) error {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		rules = append(rules, landlock.BindTCP(extractPort(*infoAddr)))
	}
	for _, section := range sections {
		switch section := section.(type) {
		case *wireproxyawg.TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *wireproxyawg.HTTPConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *wireproxyawg.TCPClientTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(uint16(section.BindAddress.Port)))
		case *wireproxyawg.Socks5Config:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		}
	}
	return landlock.V4.BestEffort().RestrictNet(rules...)
}

func main() {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-sigs
		cancel()
	}()

	exePath := executablePath()
	if err := lock("boot"); err != nil {
		log.Fatalf("Lock boot failed: %v", err)
	}

	isDaemonProcess := len(os.Args) > 1 && os.Args[1] == daemonProcess
	args := os.Args
	if isDaemonProcess {
		if err := lock("boot-daemon"); err != nil {
			log.Fatalf("Lock boot-daemon failed: %v", err)
		}
		args = []string{args[0]}
		args = append(args, os.Args[2:]...)
	}

	parser := argparse.NewParser("wireproxy", "Userspace wireguard client for proxying")
	config := parser.String("c", "config", &argparse.Options{Help: "Path of configuration file"})
	silent := parser.Flag("s", "silent", &argparse.Options{Help: "Silent mode"})
	daemon := parser.Flag("d", "daemon", &argparse.Options{Help: "Make wireproxy run in background"})
	info := parser.String("i", "info", &argparse.Options{Help: "Specify the address and port for exposing health status"})
	printVerison := parser.Flag("v", "version", &argparse.Options{Help: "Print version"})
	configTest := parser.Flag("n", "configtest", &argparse.Options{Help: "Configtest mode. Only check the configuration file for validity."})

	err := parser.Parse(args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
	}

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
			log.Fatalf("Lock read-config failed: %v", err)
		}
	}

	conf, err := wireproxyawg.ParseConfig(*config)
	if err != nil {
		log.Fatalf("Parse config failed: %v", err)
	}

	if *configTest {
		fmt.Println("Config OK")
		return
	}

	if err := lockNetwork(conf.Routines, info); err != nil {
		log.Fatalf("Lock network failed: %v", err)
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

	// redirect stdout to stderr
	os.Stdout = os.NewFile(uintptr(syscall.Stderr), "/dev/stderr")
	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	if err := lock("ready"); err != nil {
		log.Fatalf("Lock ready failed: %v", err)
	}

	tun, err := wireproxyawg.StartWireguard(conf.Device, logLevel, conf.PingCacheSize)
	if err != nil {
		log.Fatalf("Start wireguard failed: %v", err)
	}
	tun.DnsCacheSize = conf.DnsCacheSize
	tun.UdpSessionCacheSize = conf.UdpSessionCacheSize

	for _, spawner := range conf.Routines {
		go spawner.SpawnRoutine(tun)
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
				log.Printf("metrics server error: %v", err)
			}
		}()
	}

	// wait for signal
	<-ctx.Done()
	log.Println("Shutting down gracefully...")

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
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}
	if tun.Dev != nil {
		tun.Dev.Close()
	}
	<-shutdownCtx.Done()
	log.Println("Shutdown complete")
}
