package wireproxy

import (
	"net"
	"net/netip"
	"os"
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

	resolver *fixedResolver
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
	DnsTtl              int

	DnsCacheSizeSet        bool
	PingCacheSizeSet       bool
	UdpSessionCacheSizeSet bool
	DnsTtlSet              bool
}
