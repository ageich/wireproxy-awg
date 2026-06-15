package wireproxy

import (
    "context"
    "net"
    "time"
    "github.com/things-go/go-socks5"
    "github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

type fixedResolver struct {
    tnet        *netstack.Net
    systemDNS   bool
    cache       *sync.Map // <- Безопасное хранилище
    ttl         time.Duration
    cleanupFreq time.Duration
}

func NewFixedResolver(tnet *netstack.Net, systemDNS bool, ttl, cleanupFreq time.Duration) *fixedResolver {
    r := &fixedResolver{
        tnet:        tnet,
        systemDNS:   systemDNS,
        cache:       &sync.Map{},
        ttl:         ttl,
        cleanupFreq: cleanupFreq,
    }
    go r.startCleanup()
    return r
}

func (r *fixedResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
    if cached, ok := r.cache.Load(name); ok {
        entry := cached.(*cacheEntry)
        if time.Since(entry.created) < r.ttl { return ctx, entry.ip, nil }
        r.cache.Delete(name) // Удаляем устаревшую запись
    }

    var ip net.IP
    var err error
    if r.systemDNS {
        ip, err = r.resolveSystem(name)
    } else {
        ip, err = r.resolveViaTunnel(ctx, name)
    }
    if err == nil { r.cache.Store(name, &cacheEntry{ip: ip, created: time.Now()}) }
    return ctx, ip, err
}

func (r *fixedResolver) startCleanup() {
    ticker := time.NewTicker(r.cleanupFreq)
    for range ticker.C {
        r.cache.Range(func(key, value any) bool {
            if time.Since(value.(*cacheEntry).created) >= r.ttl { r.cache.Delete(key) }
            return true
        })
    }
}

type cacheEntry struct { ip net.IP; created time.Time }

func (r *fixedResolver) resolveSystem(name string) (net.IP, error) {
    ips, err := net.DefaultResolver.LookupIP(context.Background(), "ip", name)
    if err != nil || len(ips) == 0 { return nil, err }
    return ips[0], nil
}

func (r *fixedResolver) resolveViaTunnel(ctx context.Context, name string) (net.IP, error) {
    addr, err := r.tnet.LookupContextHost(ctx, name)
    if err != nil || len(addr) == 0 { return nil, err }
    return net.ParseIP(addr[0]), nil
}
