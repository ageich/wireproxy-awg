package wireproxy

import (
	"fmt"

	"github.com/go-ini/ini"
)

func ParseConfig(
	path string,
) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	cfg, err :=
		ini.LoadSources(
			iniOpt,
			path,
		)
	if err != nil {
		return nil, err
	}

	device := &DeviceConfig{
		MTU: 1420,
	}

	resolve := &ResolveConfig{
		ResolveStrategy: "auto",
	}

	// ------------------------------------------------------------
	// WireGuard config
	// ------------------------------------------------------------

	root := cfg.Section("")

	wgConf, err :=
		root.GetKey("WGConfig")

	wgCfg := cfg

	if err == nil {
		wgCfg, err =
			ini.LoadSources(
				iniOpt,
				wgConf.String(),
			)
		if err != nil {
			return nil, err
		}
	}

	if err := ParseInterface(
		wgCfg,
		device,
	); err != nil {
		return nil, err
	}

	if err := ParsePeers(
		wgCfg,
		&device.Peers,
	); err != nil {
		return nil, err
	}

	if err := validateDeviceConfig(
		device,
	); err != nil {
		return nil,
			fmt.Errorf(
				"invalid device config: %w",
				err,
			)
	}

	// ------------------------------------------------------------
	// Routines
	// ------------------------------------------------------------

	var routines []RoutineSpawner

	if err := parseRoutinesConfig(
		&routines,
		cfg,
		"TCPClientTunnel",
		parseTCPClientTunnelConfig,
	); err != nil {
		return nil, err
	}

	if err := parseRoutinesConfig(
		&routines,
		cfg,
		"STDIOTunnel",
		parseSTDIOTunnelConfig,
	); err != nil {
		return nil, err
	}

	if err := parseRoutinesConfig(
		&routines,
		cfg,
		"TCPServerTunnel",
		parseTCPServerTunnelConfig,
	); err != nil {
		return nil, err
	}

	if err := parseRoutinesConfig(
		&routines,
		cfg,
		"Socks5",
		parseSocks5Config,
	); err != nil {
		return nil, err
	}

	if err := parseRoutinesConfig(
		&routines,
		cfg,
		"http",
		parseHTTPConfig,
	); err != nil {
		return nil, err
	}

	// ------------------------------------------------------------
	// Resolve
	// ------------------------------------------------------------

	if resolveSection, err :=
		cfg.GetSection("Resolve"); err == nil {

		resolve, err =
			parseResolveConfig(
				resolveSection,
			)
		if err != nil {
			return nil, err
		}
	}

	// ------------------------------------------------------------
	// UDP
	// ------------------------------------------------------------

	if err := parseRoutinesConfig(
		&routines,
		cfg,
		"UDPProxyTunnel",
		parseUDPProxyTunnelConfig,
	); err != nil {
		return nil, err
	}

	// ------------------------------------------------------------
	// Configuration
	// ------------------------------------------------------------

	config := &Configuration{
		Device:   device,
		Routines: routines,
		Resolve:  resolve,

		DnsCacheSize:        defaultDnsCacheSize,
		PingCacheSize:       defaultPingCacheSize,
		UdpSessionCacheSize: defaultUdpSessionCacheSize,
		DnsTtl:              defaultDnsTTL,
	}

	parseCacheConfig(
		cfg,
		config,
	)

	return config, nil
}
