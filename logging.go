package main

import (
	wireproxyawg "github.com/ageich/wireproxy-awg"
)

func setWireproxyLogLevel(
	level string,
) error {
	return wireproxyawg.SetLogLevel(level)
}
