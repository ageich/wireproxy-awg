package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	wireproxyawg "github.com/ageich/wireproxy-awg"
)

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

		timer := time.NewTimer(restartDelay)

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
