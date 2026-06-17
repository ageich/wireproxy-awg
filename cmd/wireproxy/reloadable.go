package wireproxy

// Reloadable позволяет динамически перезагружать конфигурацию.
type Reloadable interface {
	Reload(newConfig *Configuration) error
}

// Реализация Reload для Socks5Config
func (c *Socks5Config) Reload(newConfig *Configuration) error {
	if c.resolver != nil {
		c.resolver.SetCacheSize(newConfig.DnsCacheSize)
	}
	return nil
}

// Реализация Reload для UDPProxyTunnelConfig
func (c *UDPProxyTunnelConfig) Reload(newConfig *Configuration) error {
	return c.SetCacheSize(newConfig.UdpSessionCacheSize)
}
