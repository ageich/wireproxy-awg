package wireproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/hashicorp/golang-lru/v2/expirable"
)

type fixedResolver struct {
	tnet       *netstack.Net
	systemDNS  bool
	cache      *expirable.LRU[string, net.IP]
	defaultTTL time.Duration
	mu         sync.RWMutex
}

func NewFixedResolver(tnet *netstack.Net, systemDNS bool, defaultTTL time.Duration, cacheSize int) *fixedResolver {
	cache := expirable.NewLRU[string, net.IP](cacheSize, nil, defaultTTL)
	return &fixedResolver{
		tnet:       tnet,
		systemDNS:  systemDNS,
		cache:      cache,
		defaultTTL: defaultTTL,
	}
}

func (r *fixedResolver) SetCacheSize(newSize int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if newSize < 1 {
		newSize = 1
	}
	if r.cache == nil {
		r.cache = expirable.NewLRU[string, net.IP](newSize, nil, r.defaultTTL)
		return
	}
	currentSize := r.cache.Len()
	if newSize > currentSize {
		r.cache = expirable.NewLRU[string, net.IP](newSize, nil, r.defaultTTL)
		return
	}
	newCache := expirable.NewLRU[string, net.IP](newSize, nil, r.defaultTTL)
	for _, key := range r.cache.Keys() {
		if val, ok := r.cache.Get(key); ok {
			newCache.Add(key, val)
		}
	}
	r.cache = newCache
}

func (r *fixedResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	r.mu.RLock()
	ip, ok := r.cache.Get(name)
	r.mu.RUnlock()
	if ok {
		return ctx, ip, nil
	}

	var ipNet net.IP
	var err error

	if r.systemDNS {
		ipNet, err = r.resolveSystemDNS(ctx, name)
	} else {
		ipNet, err = r.resolveOverTun(ctx, name)
	}
	if err != nil {
		return ctx, nil, err
	}

	r.mu.Lock()
	r.cache.Add(name, ipNet)
	r.mu.Unlock()
	return ctx, ipNet, nil
}

// Используем системный резолвер (уважает /etc/resolv.conf)
func (r *fixedResolver) resolveSystemDNS(ctx context.Context, name string) (net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", name)
	if err != nil || len(ips) == 0 {
		return nil, err
	}
	return ips[0], nil
}

func (r *fixedResolver) resolveOverTun(ctx context.Context, name string) (net.IP, error) {
	addrs, err := r.tnet.LookupContextHost(ctx, name)
	if err != nil || len(addrs) == 0 {
		return nil, err
	}
	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return nil, errors.New("failed to parse IP")
	}
	return ip, nil
}

func (r *fixedResolver) Stop() {}
