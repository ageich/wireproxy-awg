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

// ... (все константы, переменные, функции lock, executablePath, configFilePath, extractPort, lockNetwork, parseSize, setMemoryLimitFromEnvAndFlags, adjustCacheSizes, startMemoryMonitor, runWithRestart остаются без изменений, как в предыдущей версии) ...

func main() {
	// Контекст для graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)

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
	memlimit := parser.Int("", "max-memory", &argparse.Options{Help: "Set maximum memory limit in megabytes (overrides GOMEMLIMIT env if set)"})

	err := parser.Parse(args)
	if err != nil {
		fmt.Print(parser.Usage(err))
		os.Exit(1)
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

	os.Stdout = os.NewFile(uintptr(syscall.Stderr), "/dev/stderr")
	logLevel := device.LogLevelVerbose
	if *silent {
		logLevel = device.LogLevelSilent
	}

	if err := lock("ready"); err != nil {
		log.Fatalf("Lock ready failed: %v", err)
	}

	// Динамическая подстройка кэшей (если они не заданы явно)
	adjustCacheSizes(conf, limitBytes)

	tun, err := wireproxyawg.StartWireguard(conf.Device, logLevel, conf.PingCacheSize)
	if err != nil {
		log.Fatalf("Start wireguard failed: %v", err)
	}
	tun.DnsCacheSize = conf.DnsCacheSize
	tun.UdpSessionCacheSize = conf.UdpSessionCacheSize
	tun.DnsTtl = time.Duration(conf.DnsTtl) * time.Second // <-- НОВАЯ СТРОКА

	// Запускаем каждый туннель с автоматическим перезапуском при ошибке
	restartDelay := 5 * time.Second
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
				log.Printf("metrics server error: %v", err)
			}
		}()
	}

	// Запускаем периодический мониторинг памяти (каждые 5 минут)
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
				log.Println("Received SIGHUP, reloading configuration...")
				newConf, err := wireproxyawg.ParseConfig(*config)
				if err != nil {
					log.Printf("Failed to reload config: %v", err)
					continue
				}
				for _, rl := range reloadables {
					if err := rl.Reload(newConf); err != nil {
						log.Printf("Reload failed for %T: %v", rl, err)
					}
				}
				tun.DnsCacheSize = newConf.DnsCacheSize
				tun.UdpSessionCacheSize = newConf.UdpSessionCacheSize
				tun.DnsTtl = time.Duration(newConf.DnsTtl) * time.Second // обновляем TTL при перезагрузке
				log.Println("Configuration reloaded successfully")
			default:
				cancel()
				return
			}
		}
	}()

	// Ожидание отмены контекста
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
