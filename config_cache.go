package wireproxy

import (
	"github.com/go-ini/ini"
)

const (
	defaultDnsCacheSize        = 1000
	defaultPingCacheSize       = 500
	defaultUdpSessionCacheSize = 500
	defaultDnsTTL              = 300
)

func parseCacheConfig(
	cfg *ini.File,
	config *Configuration,
) {
	if cacheSection, err :=
		cfg.GetSection("Cache"); err == nil {

		if key, err :=
			cacheSection.GetKey(
				"DnsCacheSize",
			); err == nil {

			if val, err :=
				key.Int(); err == nil &&
				val > 0 {

				config.DnsCacheSize = val
				config.DnsCacheSizeSet = true
			}
		}

		if key, err :=
			cacheSection.GetKey(
				"PingCacheSize",
			); err == nil {

			if val, err :=
				key.Int(); err == nil &&
				val > 0 {

				config.PingCacheSize = val
				config.PingCacheSizeSet = true
			}
		}

		if key, err :=
			cacheSection.GetKey(
				"UdpSessionCacheSize",
			); err == nil {

			if val, err :=
				key.Int(); err == nil &&
				val > 0 {

				config.UdpSessionCacheSize = val
				config.UdpSessionCacheSizeSet = true
			}
		}

		if key, err :=
			cacheSection.GetKey(
				"DnsTtl",
			); err == nil {

			if val, err :=
				key.Int(); err == nil &&
				val > 0 {

				config.DnsTtl = val
				config.DnsTtlSet = true
			}
		}
	}
}
