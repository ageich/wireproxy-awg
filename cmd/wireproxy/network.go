package main

import (
	"fmt"
	"net"
	"strconv"

	wireproxyawg "github.com/ageich/wireproxy-awg"
	"github.com/landlock-lsm/go-landlock/landlock"
)

func extractPort(addr string) (uint16, error) {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf(
			"failed to extract port from %s: %w",
			addr,
			err,
		)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, fmt.Errorf(
			"failed to parse port from %s: %w",
			addr,
			err,
		)
	}

	if port < 0 || port > 65535 {
		return 0, fmt.Errorf(
			"port out of range in %s: %d",
			addr,
			port,
		)
	}

	return uint16(port), nil
}

func lockNetwork(
	sections []wireproxyawg.RoutineSpawner,
	infoAddr *string,
	pprofAddr *string,
) error {
	var rules []landlock.Rule

	if infoAddr != nil && *infoAddr != "" {
		port, err := extractPort(*infoAddr)
		if err != nil {
			return err
		}

		rules = append(
			rules,
			landlock.BindTCP(port),
		)
	}

	if pprofAddr != nil && *pprofAddr != "" {
		port, err := extractPort(*pprofAddr)
		if err != nil {
			return err
		}

		rules = append(
			rules,
			landlock.BindTCP(port),
		)
	}

	for _, section := range sections {
		switch section := section.(type) {

		case *wireproxyawg.TCPServerTunnelConfig:
			port, err := extractPort(section.Target)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.ConnectTCP(port),
			)

		case *wireproxyawg.HTTPConfig:
			port, err := extractPort(section.BindAddress)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.BindTCP(port),
			)

		case *wireproxyawg.TCPClientTunnelConfig:
			if section.BindAddress == nil {
				return fmt.Errorf(
					"TCP client bind address is nil",
				)
			}

			port, err := extractPort(
				section.BindAddress.String(),
			)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.BindTCP(port),
			)

		case *wireproxyawg.Socks5Config:
			port, err := extractPort(
				section.BindAddress,
			)
			if err != nil {
				return err
			}

			rules = append(
				rules,
				landlock.BindTCP(port),
			)
		}
	}

	if len(rules) == 0 {
		return nil
	}

	return landlock.V4.BestEffort().RestrictNet(
		rules...,
	)
}
