package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
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

func startRoutines(
	ctx context.Context,
	routines []wireproxyawg.RoutineSpawner,
	tun *wireproxyawg.VirtualTun,
	restartDelay time.Duration,
	wg *sync.WaitGroup,
) {
	for _, spawner := range routines {
		if spawner == nil {
			continue
		}

		wg.Add(1)

		go func(
			spawner wireproxyawg.RoutineSpawner,
		) {
			defer wg.Done()

			runWithRestart(
				ctx,
				spawner,
				tun,
				restartDelay,
			)
		}(spawner)
	}
}

func collectReloadables(
	routines []wireproxyawg.RoutineSpawner,
) []wireproxyawg.Reloadable {
	reloadables := make(
		[]wireproxyawg.Reloadable,
		0,
	)

	for _, routine := range routines {
		if reloadable, ok :=
			routine.(wireproxyawg.Reloadable); ok {

			reloadables = append(
				reloadables,
				reloadable,
			)
		}
	}

	return reloadables
}

func stopSocks5Routines(
	routines []wireproxyawg.RoutineSpawner,
) {
	for _, spawner := range routines {
		s5, ok :=
			spawner.(*wireproxyawg.Socks5Config)

		if !ok {
			continue
		}

		s5.Stop()
	}
}

func waitRoutines(
	ctx context.Context,
	wg *sync.WaitGroup,
) {
	routinesDone := make(
		chan struct{},
	)

	go func() {
		wg.Wait()
		close(routinesDone)
	}()

	select {
	case <-routinesDone:
		slog.Debug(
			"All routine goroutines stopped",
		)

	case <-ctx.Done():
		slog.Warn(
			"Routine shutdown timed out",
		)
	}
}
