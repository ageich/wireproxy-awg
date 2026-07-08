package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
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

// ... (все константы, переменные, функции lock, executablePath, configFilePath, extractPort, lockNetwork, parseSize, setMemoryLimitFromEnvAndFlags, adjustCacheSizes, startMemoryMonitor, runWithRestart остаются без изменений) ...

func main() {
	// Инициализация логирования
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

	// Основной контекст – без таймаута (работает до получения сигнала)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

	exePath := executablePath()
	if err := lock("boot"); err != nil {
		slog.Error("Lock boot failed", "error", err)
		os.Exit(1)
	}

	// ... (вся остальная логика до запуска туннелей без изменений) ...

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

	if err := lockNetwork(conf.Routines, info); err != nil {
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

	// Запуск туннелей с перезапуском
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

	// Собираем объекты, поддерживающие перезагрузку
	var reloadables []wireproxyawg.Reloadable
	for _, r := range conf.Routines {
		if rl, ok := r.(wireproxyawg.Reloadable); ok {
			reloadables = append(reloadables, rl)
		}
	}

	// Обработка сигналов
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
				cancel() // отменяем основной контекст
				return
			}
		}
	}()

	// Ожидаем отмены контекста (сигнал)
	<-ctx.Done()
	slog.Info("Shutting down gracefully...")

	// Graceful shutdown с таймаутом 5 секунд на закрытие соединений
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
