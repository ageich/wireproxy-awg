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

func startSignalHandler(
	ctx context.Context,
	cancel context.CancelFunc,
	sigCh <-chan os.Signal,
	configPath string,
	reloadables []wireproxyawg.Reloadable,
	tun *wireproxyawg.VirtualTun,
) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return

			case sig := <-sigCh:
				switch sig {
				case syscall.SIGHUP:
					reloadConfiguration(
						configPath,
						reloadables,
						tun,
					)

				default:
					cancel()
					return
				}
			}
		}
	}()
}

func reloadConfiguration(
	configPath string,
	reloadables []wireproxyawg.Reloadable,
	tun *wireproxyawg.VirtualTun,
) {
	slog.Info(
		"Received SIGHUP, reloading configuration...",
	)

	newConf, err :=
		wireproxyawg.ParseConfig(
			configPath,
		)
	if err != nil {
		slog.Error(
			"Failed to reload config",
			"error",
			err,
		)
		return
	}

	for _, reloadable := range reloadables {
		if err := reloadable.Reload(
			newConf,
		); err != nil {
			slog.Error(
				"Reload failed",
				"routine",
				fmt.Sprintf(
					"%T",
					reloadable,
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
}
