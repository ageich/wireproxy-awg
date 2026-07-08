package wireproxy

import (
	"bytes"
	"fmt"
	"strings"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	lru "github.com/hashicorp/golang-lru/v2"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

// validateDeviceConfig проверяет обязательные поля конфигурации перед построением IPC.
func validateDeviceConfig(conf *DeviceConfig) error {
	if conf.SecretKey == "" {
		return fmt.Errorf("PrivateKey is required")
	}
	if len(conf.SecretKey) != 64 {
		return fmt.Errorf("PrivateKey must be 64 hex characters (32 bytes)")
	}
	if len(conf.Peers) == 0 {
		return fmt.Errorf("at least one Peer is required")
	}
	for i, peer := range conf.Peers {
		if peer.PublicKey == "" {
			return fmt.Errorf("Peer[%d]: PublicKey is required", i)
		}
		if len(peer.PublicKey) != 64 {
			return fmt.Errorf("Peer[%d]: PublicKey must be 64 hex characters (32 bytes)", i)
		}
		if peer.Endpoint == nil || *peer.Endpoint == "" {
			return fmt.Errorf("Peer[%d]: Endpoint is required", i)
		}
		if len(peer.AllowedIPs) == 0 {
			return fmt.Errorf("Peer[%d]: at least one AllowedIP is required", i)
		}
	}
	return nil
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
// Оптимизировано: предварительное выделение буфера для уменьшения перераспределений.
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	// Валидация перед построением IPC
	if err := validateDeviceConfig(conf); err != nil {
		return nil, fmt.Errorf("invalid device config: %w", err)
	}

	var request bytes.Buffer
	request.Grow(4096)

	fmt.Fprintf(&request, "private_key=%s\n", conf.SecretKey)

	if conf.ListenPort != nil {
		fmt.Fprintf(&request, "listen_port=%d\n", *conf.ListenPort)
	}

	if conf.ASecConfig != nil {
		aSecConfig := conf.ASecConfig

		var aSecBuilder strings.Builder
		if aSecConfig.hasJunkPacketCount {
			fmt.Fprintf(&aSecBuilder, "jc=%d\n", aSecConfig.junkPacketCount)
		}
		if aSecConfig.hasJunkPacketMinSize {
			fmt.Fprintf(&aSecBuilder, "jmin=%d\n", aSecConfig.junkPacketMinSize)
		}
		if aSecConfig.hasJunkPacketMaxSize {
			fmt.Fprintf(&aSecBuilder, "jmax=%d\n", aSecConfig.junkPacketMaxSize)
		}
		if aSecConfig.hasInitPacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s1=%d\n", aSecConfig.initPacketJunkSize)
		}
		if aSecConfig.hasResponsePacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s2=%d\n", aSecConfig.responsePacketJunkSize)
		}
		if aSecConfig.hasCookieReplyPacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s3=%d\n", aSecConfig.cookieReplyPacketJunkSize)
		}
		if aSecConfig.hasTransportPacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s4=%d\n", aSecConfig.transportPacketJunkSize)
		}
		if aSecConfig.hasInitPacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h1=%s\n",
				formatMagicHeaderInterval(aSecConfig.initPacketMagicHeader, aSecConfig.initPacketMagicHeaderMax),
			)
		}
		if aSecConfig.hasResponsePacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h2=%s\n",
				formatMagicHeaderInterval(aSecConfig.responsePacketMagicHeader, aSecConfig.responsePacketMagicHeaderMax),
			)
		}
		if aSecConfig.hasUnderloadPacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h3=%s\n",
				formatMagicHeaderInterval(aSecConfig.underloadPacketMagicHeader, aSecConfig.underloadPacketMagicHeaderMax),
			)
		}
		if aSecConfig.hasTransportPacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h4=%s\n",
				formatMagicHeaderInterval(aSecConfig.transportPacketMagicHeader, aSecConfig.transportPacketMagicHeaderMax),
			)
		}
		if aSecConfig.i1 != nil {
			fmt.Fprintf(&aSecBuilder, "i1=%s\n", *aSecConfig.i1)
		}
		if aSecConfig.i2 != nil {
			fmt.Fprintf(&aSecBuilder, "i2=%s\n", *aSecConfig.i2)
		}
		if aSecConfig.i3 != nil {
			fmt.Fprintf(&aSecBuilder, "i3=%s\n", *aSecConfig.i3)
		}
		if aSecConfig.i4 != nil {
			fmt.Fprintf(&aSecBuilder, "i4=%s\n", *aSecConfig.i4)
		}
		if aSecConfig.i5 != nil {
			fmt.Fprintf(&aSecBuilder, "i5=%s\n", *aSecConfig.i5)
		}

		request.WriteString(aSecBuilder.String())
	}

	for _, peer := range conf.Peers {
		fmt.Fprintf(&request, heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		)
		if peer.Endpoint != nil {
			fmt.Fprintf(&request, "endpoint=%s\n", *peer.Endpoint)
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				fmt.Fprintf(&request, "allowed_ip=%s\n", ip.String())
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{
		IpcRequest: request.String(),
		DNS:        conf.DNS,
		DeviceAddr: conf.Endpoint,
		MTU:        conf.MTU,
	}
	return setting, nil
}

// StartWireguard creates a tun interface on netstack given a configuration.
// pingCacheSize задаёт максимальное количество записей в кэше PingRecord (LRU).
func StartWireguard(conf *DeviceConfig, logLevel int, pingCacheSize int) (*VirtualTun, error) {
	setting, err := CreateIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	err = dev.IpcSet(setting.IpcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	// Создаём LRU-кэш для хранения времени последнего успешного ping-а
	pingCache, err := lru.New[string, uint64](pingCacheSize)
	if err != nil {
		return nil, err
	}

	return &VirtualTun{
		Tnet:       tnet,
		Dev:        dev,
		Conf:       conf,
		SystemDNS:  len(setting.DNS) == 0,
		PingRecord: pingCache,
	}, nil
}
