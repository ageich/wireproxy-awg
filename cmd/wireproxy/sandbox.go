package main

import (
	"fmt"
	"net"
	"os"

	"github.com/landlock-lsm/go-landlock/landlock"
	"suah.dev/protect"
)

func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}

	return programPath
}

func lock(stage string) error {
	switch stage {

	case "boot":
		exePath := executablePath()

		if err := protect.Unveil("/", "r"); err != nil {
			return fmt.Errorf(
				"unveil /: %w",
				err,
			)
		}

		if err := protect.Unveil(exePath, "x"); err != nil {
			return fmt.Errorf(
				"unveil %s: %w",
				exePath,
				err,
			)
		}

		if err := protect.Pledge(
			"stdio rpath inet dns proc exec",
		); err != nil {
			return fmt.Errorf(
				"pledge: %w",
				err,
			)
		}

		if err := landlock.V1.BestEffort().RestrictPaths(
			landlock.RODirs("/"),
		); err != nil {
			return fmt.Errorf(
				"landlock: %w",
				err,
			)
		}

	case "boot-daemon":
		// Daemon inherits the sandbox.

	case "read-config":
		if err := protect.Pledge(
			"stdio rpath inet dns",
		); err != nil {
			return fmt.Errorf(
				"pledge: %w",
				err,
			)
		}

	case "ready":
		if err := protect.Pledge(
			"stdio inet dns",
		); err != nil {
			return fmt.Errorf(
				"pledge: %w",
				err,
			)
		}

		net.DefaultResolver.PreferGo = true

		if err := landlock.V1.BestEffort().RestrictPaths(

			landlock.ROFiles(
				"/etc/resolv.conf",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/dev/fd",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/dev/zero",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/dev/urandom",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/etc/localtime",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/self/stat",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/self/status",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/usr/share/locale",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/self/cmdline",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/usr/share/zoneinfo",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/kernel/version",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/kernel/ngroups_max",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/kernel/cap_last_cap",
			).IgnoreIfMissing(),

			landlock.ROFiles(
				"/proc/sys/vm/overcommit_memory",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/dev/log",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/dev/null",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/dev/full",
			).IgnoreIfMissing(),

			landlock.RWFiles(
				"/proc/self/fd",
			).IgnoreIfMissing(),
		); err != nil {
			return fmt.Errorf(
				"landlock: %w",
				err,
			)
		}

	default:
		return fmt.Errorf(
			"invalid stage %s",
			stage,
		)
	}

	return nil
}
