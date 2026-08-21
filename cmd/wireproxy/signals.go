package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"time"

	wireproxyawg "github.com/ageich/wireproxy-awg"
)

func handleSignals(
	ctx context.Context,
	cancel context.CancelFunc,
	sigCh <-chan os.Signal,
	configPath string,
	tun *wireproxyawg.VirtualTun,
	reloadables []wireproxyawg.Reloadable,
) {
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

				newConf, err := wireproxyawg.ParseConfig(
					configPath,
				)
				if err != nil {
					slog.Error(
						"Failed to reload config",
						"error",
						err,
					)
					continue
				}

				reloadOK := true

				for _, rl := range reloadables {
					if rl == nil {
						continue
					}

					if err := rl.Reload(newConf); err != nil {
						reloadOK = false

						slog.Error(
							"Reload failed",
							"routine",
							fmt.Sprintf("%T", rl),
							"error",
							err,
						)
					}
				}

				if tun != nil {
					tun.DnsCacheSize =
						newConf.DnsCacheSize

					tun.UdpSessionCacheSize =
						newConf.UdpSessionCacheSize

					tun.DnsTtl =
						time.Duration(
							newConf.DnsTtl,
						) * time.Second
				}

				if reloadOK {
					slog.Info(
						"Configuration reloaded successfully",
					)
				} else {
					slog.Warn(
						"Configuration reload completed with errors",
					)
				}

			case syscall.SIGINT,
				syscall.SIGTERM,
				syscall.SIGQUIT:

				slog.Info(
					"Received shutdown signal",
					"signal",
					sig.String(),
				)

				cancel()
				return

			default:
				cancel()
				return
			}
		}
	}
}
