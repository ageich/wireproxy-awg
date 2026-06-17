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

// UDPProxyTunnelConfig — определение удалено, оно теперь в udp_proxy.go

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
}

// ... остальные функции (parseString, parsePort, parseTCPAddr, ...) без изменений

// parseUDPProxyTunnelConfig остаётся без изменений, т.к. структура определена в udp_proxy.go
func parseUDPProxyTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
    config := &UDPProxyTunnelConfig{}
    bindAddress, err := parseString(section, "BindAddress")
    if err != nil {
        return nil, err
    }
    config.BindAddress = bindAddress

    target, err := parseString(section, "Target")
    if err != nil {
        return nil, err
    }
    config.Target = target

    inactivityTimeout := 0
    if sectionKey, err := section.GetKey("InactivityTimeout"); err == nil {
        timeoutVal, err := sectionKey.Int()
        if err != nil {
            return nil, err
        }
        inactivityTimeout = timeoutVal
    }
    config.InactivityTimeout = inactivityTimeout

    return config, nil
}

// ... остальные функции ParseConfig и т.д.
