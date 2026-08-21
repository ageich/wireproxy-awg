package wireproxy

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/go-ini/ini"
)

func parseString(
	section *ini.Section,
	keyName string,
) (string, error) {
	key := section.Key(
		strings.ToLower(keyName),
	)

	if key == nil {
		return "",
			errors.New(
				keyName + " should not be empty",
			)
	}

	value := key.String()

	if strings.HasPrefix(value, "$") {
		if strings.HasPrefix(value, "$$") {
			return strings.Replace(
				value,
				"$$",
				"$",
				1,
			), nil
		}

		envName := strings.TrimPrefix(
			value,
			"$",
		)

		envValue, ok :=
			os.LookupEnv(envName)

		if !ok {
			return "",
				errors.New(
					keyName +
						" references unset environment variable " +
						key.String(),
				)
		}

		return envValue, nil
	}

	return value, nil
}

func parsePort(
	section *ini.Section,
	keyName string,
) (int, error) {
	key := section.Key(keyName)

	if key == nil {
		return 0,
			errors.New(
				keyName + " should not be empty",
			)
	}

	port, err := key.Int()
	if err != nil {
		return 0, err
	}

	if port < 0 || port >= 65536 {
		return 0,
			errors.New(
				"port should be >= 0 and < 65536",
			)
	}

	return port, nil
}

func parseTCPAddr(
	section *ini.Section,
	keyName string,
) (*net.TCPAddr, error) {
	addrStr, err :=
		parseString(
			section,
			keyName,
		)
	if err != nil {
		return nil, err
	}

	return net.ResolveTCPAddr(
		"tcp",
		addrStr,
	)
}

func parseBase64KeyToHex(
	section *ini.Section,
	keyName string,
) (string, error) {
	key, err :=
		parseString(
			section,
			keyName,
		)
	if err != nil {
		return "", err
	}

	return encodeBase64ToHex(key)
}

func encodeBase64ToHex(
	key string,
) (string, error) {
	decoded, err :=
		base64.StdEncoding.DecodeString(key)

	if err != nil {
		return "",
			errors.New(
				"invalid base64 string: " + key,
			)
	}

	if len(decoded) != 32 {
		return "",
			errors.New(
				"key should be 32 bytes: " + key,
			)
	}

	return hex.EncodeToString(decoded), nil
}

func parseNetIP(
	section *ini.Section,
	keyName string,
) ([]netip.Addr, error) {
	key, err :=
		parseString(
			section,
			keyName,
		)

	if err != nil {
		if strings.Contains(
			err.Error(),
			"should not be empty",
		) {
			return []netip.Addr{}, nil
		}

		return nil, err
	}

	keys := strings.Split(
		key,
		",",
	)

	ips := make(
		[]netip.Addr,
		0,
		len(keys),
	)

	for _, str := range keys {
		str = strings.TrimSpace(str)

		if str == "" {
			continue
		}

		ip, err :=
			netip.ParseAddr(str)

		if err != nil {
			return nil, err
		}

		ips = append(
			ips,
			ip,
		)
	}

	return ips, nil
}

func parseCIDRNetIP(
	section *ini.Section,
	keyName string,
) ([]netip.Addr, error) {
	key, err :=
		parseString(
			section,
			keyName,
		)

	if err != nil {
		if strings.Contains(
			err.Error(),
			"should not be empty",
		) {
			return []netip.Addr{}, nil
		}

		return nil, err
	}

	keys := strings.Split(
		key,
		",",
	)

	ips := make(
		[]netip.Addr,
		0,
		len(keys),
	)

	for _, str := range keys {
		str = strings.TrimSpace(str)

		if str == "" {
			continue
		}

		if addr, err :=
			netip.ParseAddr(str); err == nil {

			ips = append(
				ips,
				addr,
			)

			continue
		}

		prefix, err :=
			netip.ParsePrefix(str)

		if err != nil {
			return nil, err
		}

		ips = append(
			ips,
			prefix.Addr(),
		)
	}

	return ips, nil
}

func parseAllowedIPs(
	section *ini.Section,
) ([]netip.Prefix, error) {
	key, err :=
		parseString(
			section,
			"AllowedIPs",
		)

	if err != nil {
		if strings.Contains(
			err.Error(),
			"should not be empty",
		) {
			return []netip.Prefix{}, nil
		}

		return nil, err
	}

	keys := strings.Split(
		key,
		",",
	)

	ips := make(
		[]netip.Prefix,
		0,
		len(keys),
	)

	for _, str := range keys {
		str = strings.TrimSpace(str)

		if str == "" {
			continue
		}

		prefix, err :=
			netip.ParsePrefix(str)

		if err != nil {
			return nil, err
		}

		ips = append(
			ips,
			prefix,
		)
	}

	return ips, nil
}

func resolveIP(
	ip string,
) (*net.IPAddr, error) {
	return net.ResolveIPAddr(
		"ip",
		ip,
	)
}

func resolveIPPAndPort(
	addr string,
) (string, error) {
	host, port, err :=
		net.SplitHostPort(addr)

	if err != nil {
		return "", err
	}

	ip, err :=
		resolveIP(host)

	if err != nil {
		return "", err
	}

	return net.JoinHostPort(
		ip.String(),
		port,
	), nil
}
