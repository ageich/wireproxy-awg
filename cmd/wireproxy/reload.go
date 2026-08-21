package main

import (
	wireproxyawg "github.com/ageich/wireproxy-awg"
)

func collectReloadables(
	routines []wireproxyawg.RoutineSpawner,
) []wireproxyawg.Reloadable {
	if len(routines) == 0 {
		return nil
	}

	reloadables := make(
		[]wireproxyawg.Reloadable,
		0,
		len(routines),
	)

	for _, routine := range routines {
		if routine == nil {
			continue
		}

		if reloadable, ok := routine.(wireproxyawg.Reloadable); ok {
			reloadables = append(
				reloadables,
				reloadable,
			)
		}
	}

	return reloadables
}
