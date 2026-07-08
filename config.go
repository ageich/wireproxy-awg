package wireproxy

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net"
	"os"
	"strings"

	"github.com/go-ini/ini"
	"net/netip"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     *string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

type DeviceConfig struct {
	SecretKey          string
	Endpoint           []netip.Addr
	Peers              []PeerConfig
	DNS                []netip.Addr
	MTU                int
	ListenPort         *int
	CheckAlive         []netip.Addr
	CheckAliveInterval int
	ASecConfig         *ASecConfigType
}

type TCPClientTunnelConfig struct {
	BindAddress *net.TCPAddr
	Target      string
}

type STDIOTunnelConfig struct {
	Target string
	Input  *os.File
	Output *os.File
}

type TCPServerTunnelConfig struct {
	ListenPort int
	Target     string
}

type Socks5Config struct {
	BindAddress string
	Username    string
	Password    string
	resolver    *fixedResolver
}

func (c *Socks5Config) Stop() {
	if c.resolver != nil {
		c.resolver.Stop()
	}
}

type HTTPConfig struct {
	BindAddress string
	Username    string
	Password    string
	CertFile    string
	KeyFile     string
}

type ResolveConfig struct {
	ResolveStrategy string
}

type Configuration struct {
	Device   *DeviceConfig
	Routines []RoutineSpawner
	Resolve  *ResolveConfig

	DnsCacheSize        int
	PingCacheSize       int
	UdpSessionCacheSize int
	DnsTtl              int // <-- NEW: TTL для DNS-кэша в секундах

	DnsCacheSizeSet        bool
	PingCacheSizeSet       bool
	UdpSessionCacheSizeSet bool
	DnsTtlSet              bool // <-- NEW
}

// ---- Вспомогательные функции парсинга (без изменений) ----
// ... (все функции parseString, parsePort и т.д. остаются как в предыдущей версии)
// ... (ParseInterface, ParsePeers и др. без изменений)

// parseUDPProxyTunnelConfig, parseRoutinesConfig и ParseConfig с изменениями

func ParseConfig(path string) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}
	cfg, err := ini.LoadSources(iniOpt, path)
	if err != nil {
		return nil, err
	}

	device := &DeviceConfig{MTU: 1420}
	resolve := &ResolveConfig{ResolveStrategy: "auto"}

	root := cfg.Section("")
	wgConf, err := root.GetKey("WGConfig")
	wgCfg := cfg
	if err == nil {
		wgCfg, err = ini.LoadSources(iniOpt, wgConf.String())
		if err != nil {
			return nil, err
		}
	}

	err = ParseInterface(wgCfg, device)
	if err != nil {
		return nil, err
	}

	err = ParsePeers(wgCfg, &device.Peers)
	if err != nil {
		return nil, err
	}

	var routinesSpawners []RoutineSpawner

	err = parseRoutinesConfig(&routinesSpawners, cfg, "TCPClientTunnel", parseTCPClientTunnelConfig)
	if err != nil {
		return nil, err
	}
	err = parseRoutinesConfig(&routinesSpawners, cfg, "STDIOTunnel", parseSTDIOTunnelConfig)
	if err != nil {
		return nil, err
	}
	err = parseRoutinesConfig(&routinesSpawners, cfg, "TCPServerTunnel", parseTCPServerTunnelConfig)
	if err != nil {
		return nil, err
	}
	err = parseRoutinesConfig(&routinesSpawners, cfg, "Socks5", parseSocks5Config)
	if err != nil {
		return nil, err
	}
	err = parseRoutinesConfig(&routinesSpawners, cfg, "http", parseHTTPConfig)
	if err != nil {
		return nil, err
	}

	if resolveSection, err := cfg.GetSection("Resolve"); err == nil {
		resolve, err = parseResolveConfig(resolveSection)
		if err != nil {
			return nil, err
		}
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "UDPProxyTunnel", parseUDPProxyTunnelConfig)
	if err != nil {
		return nil, err
	}

	config := &Configuration{
		Device:   device,
		Routines: routinesSpawners,
		Resolve:  resolve,
		// Значения по умолчанию
		DnsCacheSize:        1000,
		PingCacheSize:       500,
		UdpSessionCacheSize: 500,
		DnsTtl:              300, // 5 минут
	}

	// Чтение секции [Cache]
	if cacheSection, err := cfg.GetSection("Cache"); err == nil {
		if key, err := cacheSection.GetKey("DnsCacheSize"); err == nil {
			if val, err := key.Int(); err == nil && val > 0 {
				config.DnsCacheSize = val
				config.DnsCacheSizeSet = true
			}
		}
		if key, err := cacheSection.GetKey("PingCacheSize"); err == nil {
			if val, err := key.Int(); err == nil && val > 0 {
				config.PingCacheSize = val
				config.PingCacheSizeSet = true
			}
		}
		if key, err := cacheSection.GetKey("UdpSessionCacheSize"); err == nil {
			if val, err := key.Int(); err == nil && val > 0 {
				config.UdpSessionCacheSize = val
				config.UdpSessionCacheSizeSet = true
			}
		}
		if key, err := cacheSection.GetKey("DnsTtl"); err == nil { // <-- NEW
			if val, err := key.Int(); err == nil && val > 0 {
				config.DnsTtl = val
				config.DnsTtlSet = true
			}
		}
	}

	return config, nil
}
