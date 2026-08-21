package wireproxy

import (
	"os"

	"github.com/go-ini/ini"
)

func parseTCPClientTunnelConfig(
	section *ini.Section,
) (RoutineSpawner, error) {
	config :=
		&TCPClientTunnelConfig{}

	tcpAddr, err :=
		parseTCPAddr(
			section,
			"BindAddress",
		)
	if err != nil {
		return nil, err
	}

	config.BindAddress = tcpAddr

	target, err :=
		parseString(
			section,
			"Target",
		)
	if err != nil {
		return nil, err
	}

	config.Target = target

	return config, nil
}

func parseSTDIOTunnelConfig(
	section *ini.Section,
) (RoutineSpawner, error) {
	config :=
		&STDIOTunnelConfig{}

	target, err :=
		parseString(
			section,
			"Target",
		)
	if err != nil {
		return nil, err
	}

	config.Target = target
	config.Input = os.Stdin
	config.Output = os.Stdout

	return config, nil
}

func parseTCPServerTunnelConfig(
	section *ini.Section,
) (RoutineSpawner, error) {
	config :=
		&TCPServerTunnelConfig{}

	listenPort, err :=
		parsePort(
			section,
			"ListenPort",
		)
	if err != nil {
		return nil, err
	}

	config.ListenPort = listenPort

	target, err :=
		parseString(
			section,
			"Target",
		)
	if err != nil {
		return nil, err
	}

	config.Target = target

	return config, nil
}

func parseSocks5Config(
	section *ini.Section,
) (RoutineSpawner, error) {
	config :=
		&Socks5Config{}

	bindAddress, err :=
		parseString(
			section,
			"BindAddress",
		)
	if err != nil {
		return nil, err
	}

	config.BindAddress = bindAddress

	username, _ :=
		parseString(
			section,
			"Username",
		)

	password, _ :=
		parseString(
			section,
			"Password",
		)

	config.Username = username
	config.Password = password

	return config, nil
}

func parseHTTPConfig(
	section *ini.Section,
) (RoutineSpawner, error) {
	config :=
		&HTTPConfig{}

	bindAddress, err :=
		parseString(
			section,
			"BindAddress",
		)
	if err != nil {
		return nil, err
	}

	config.BindAddress = bindAddress

	username, _ :=
		parseString(
			section,
			"Username",
		)

	password, _ :=
		parseString(
			section,
			"Password",
		)

	certFile, _ :=
		parseString(
			section,
			"CertFile",
		)

	keyFile, _ :=
		parseString(
			section,
			"KeyFile",
		)

	config.Username = username
	config.Password = password
	config.CertFile = certFile
	config.KeyFile = keyFile

	return config, nil
}

func parseResolveConfig(
	section *ini.Section,
) (*ResolveConfig, error) {
	config :=
		&ResolveConfig{}

	resolvStrategy, _ :=
		parseString(
			section,
			"ResolveStrategy",
		)

	config.ResolveStrategy =
		resolvStrategy

	return config, nil
}

func parseUDPProxyTunnelConfig(
	section *ini.Section,
) (RoutineSpawner, error) {
	config :=
		&UDPProxyTunnelConfig{}

	bindAddress, err :=
		parseString(
			section,
			"BindAddress",
		)
	if err != nil {
		return nil, err
	}

	config.BindAddress = bindAddress

	target, err :=
		parseString(
			section,
			"Target",
		)
	if err != nil {
		return nil, err
	}

	config.Target = target

	inactivityTimeout := 0

	if sectionKey, err :=
		section.GetKey(
			"InactivityTimeout",
		); err == nil {

		timeoutVal, err :=
			sectionKey.Int()
		if err != nil {
			return nil, err
		}

		inactivityTimeout = timeoutVal
	}

	config.InactivityTimeout =
		inactivityTimeout

	return config, nil
}

func parseRoutinesConfig(
	routines *[]RoutineSpawner,
	cfg *ini.File,
	sectionName string,
	f func(*ini.Section) (RoutineSpawner, error),
) error {
	sections, err :=
		cfg.SectionsByName(sectionName)

	if err != nil {
		return nil
	}

	for _, section := range sections {
		config, err :=
			f(section)
		if err != nil {
			return err
		}

		*routines = append(
			*routines,
			config,
		)
	}

	return nil
}
