package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	wireproxyawg "github.com/ageich/wireproxy-awg"
)

func parseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)

	if s == "" {
		return 0, fmt.Errorf(
			"empty size string",
		)
	}

	lower := strings.ToLower(s)

	var multiplier int64 = 1

	switch {
	case strings.HasSuffix(lower, "kib"):
		multiplier = 1024
		s = s[:len(s)-3]

	case strings.HasSuffix(lower, "mib"):
		multiplier = 1024 * 1024
		s = s[:len(s)-3]

	case strings.HasSuffix(lower, "gib"):
		multiplier = 1024 * 1024 * 1024
		s = s[:len(s)-3]

	case strings.HasSuffix(lower, "kb"):
		multiplier = 1000
		s = s[:len(s)-2]

	case strings.HasSuffix(lower, "mb"):
		multiplier = 1000 * 1000
		s = s[:len(s)-2]

	case strings.HasSuffix(lower, "gb"):
		multiplier = 1000 * 1000 * 1000
		s = s[:len(s)-2]
	}

	valueString := strings.TrimSpace(s)

	val, err := strconv.ParseInt(
		valueString,
		10,
		64,
	)
	if err != nil {
		return 0, fmt.Errorf(
			"invalid number format: %w",
			err,
		)
	}

	if val <= 0 {
		return 0, fmt.Errorf(
			"size must be positive",
		)
	}

	const maxInt64 = int64(^uint64(0) >> 1)

	if val > maxInt64/multiplier {
		return 0, fmt.Errorf(
			"size overflows int64",
		)
	}

	return val * multiplier, nil
}

func setMemoryLimitFromEnvAndFlags(
	memlimitFlag int,
) (int64, error) {
	var limitBytes int64

	envLimit := os.Getenv(
		"GOMEMLIMIT",
	)

	if envLimit != "" {
		val, err := parseSize(envLimit)
		if err != nil {
			slog.Warn(
				"GOMEMLIMIT has invalid value",
				"value",
				envLimit,
				"error",
				err,
			)
		} else {
			limitBytes = val
		}
	}

	if memlimitFlag > 0 {
		const maxInt64 = int64(^uint64(0) >> 1)

		flagValue := int64(memlimitFlag)

		if flagValue > maxInt64/(1024*1024) {
			return 0, fmt.Errorf(
				"max-memory value is too large",
			)
		}

		limitBytes =
			flagValue *
				1024 *
				1024
	}

	if limitBytes > 0 {
		debug.SetMemoryLimit(
			limitBytes,
		)

		slog.Info(
			"Memory limit set",
			"bytes",
			limitBytes,
			"mb",
			limitBytes/(1024*1024),
			"gib",
			float64(limitBytes)/
				(1024*1024*1024),
		)
	} else {
		slog.Info(
			"No memory limit set",
			"use GOMEMLIMIT env or --max-memory flag",
		)
	}

	return limitBytes, nil
}

func adjustCacheSizes(
	conf *wireproxyawg.Configuration,
	limitBytes int64,
) {
	if conf == nil || limitBytes <= 0 {
		return
	}

	total := limitBytes / 10

	dns := int(
		float64(total)*
			0.30/
			64,
	)

	ping := int(
		float64(total)*
			0.10/
			8,
	)

	udp := int(
		float64(total)*
			0.60/
			1024,
	)

	const (
		minDns  = 100
		minPing = 50
		minUdp  = 100
	)

	if !conf.DnsCacheSizeSet {
		if dns < minDns {
			dns = minDns
		}

		conf.DnsCacheSize = dns

		slog.Info(
			"Auto-adjusted DnsCacheSize",
			"size",
			dns,
		)
	}

	if !conf.PingCacheSizeSet {
		if ping < minPing {
			ping = minPing
		}

		conf.PingCacheSize = ping

		slog.Info(
			"Auto-adjusted PingCacheSize",
			"size",
			ping,
		)
	}

	if !conf.UdpSessionCacheSizeSet {
		if udp < minUdp {
			udp = minUdp
		}

		conf.UdpSessionCacheSize = udp

		slog.Info(
			"Auto-adjusted UdpSessionCacheSize",
			"size",
			udp,
		)
	}
}

func startMemoryMonitor(
	ctx context.Context,
	interval time.Duration,
) {
	if interval <= 0 {
		return
	}

	ticker := time.NewTicker(interval)

	go func() {
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return

			case <-ticker.C:
				runtime.GC()

				slog.Debug(
					"Periodic GC completed",
				)
			}
		}
	}()
}
