package wireproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/miekg/dns"
)

// fixedResolver реализует socks5.NameResolver с LRU-кэшем и фиксированным TTL.
// Для системных запросов использует прямой UDP-запрос к 1.1.1.1:53.
type fixedResolver struct {
	tnet       *netstack.Net
	systemDNS  bool
	cache      *expirable.LRU[string, net.IP]
	defaultTTL time.Duration
	mu         sync.RWMutex
}

// NewFixedResolver создаёт новый резолвер.
func NewFixedResolver(tnet *netstack.Net, systemDNS bool, defaultTTL time.Duration, cacheSize int) *fixedResolver {
	cache := expirable.NewLRU[string, net.IP](cacheSize, nil, defaultTTL)
	return &fixedResolver{
		tnet:       tnet,
		systemDNS:  systemDNS,
		cache:      cache,
		defaultTTL: defaultTTL,
	}
}

// SetCacheSize изменяет размер кэша.
// Если новый размер больше текущего, кэш создаётся без копирования.
// Если новый размер меньше или равен, записи копируются.
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
		// При увеличении создаём новый кэш без копирования
		r.cache = expirable.NewLRU[string, net.IP](newSize, nil, r.defaultTTL)
		return
	}
	// При уменьшении или равенстве копируем записи
	newCache := expirable.NewLRU[string, net.IP](newSize, nil, r.defaultTTL)
	for _, key := range r.cache.Keys() {
		if val, ok := r.cache.Get(key); ok {
			newCache.Add(key, val)
		}
	}
	r.cache = newCache
}

// Resolve выполняет DNS-запрос.
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
	r.cache.Add(name, ipNet) // используем общий TTL кэша (defaultTTL)
	r.mu.Unlock()
	return ctx, ipNet, nil
}

// resolveSystemDNS выполняет прямой UDP-запрос к 1.1.1.1:53.
// TTL из ответа игнорируется – используется defaultTTL из кэша.
func (r *fixedResolver) resolveSystemDNS(ctx context.Context, name string) (net.IP, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := c.ExchangeContext(ctx, m, "1.1.1.1:53")
	if err != nil {
		return nil, err
	}
	if len(resp.Answer) == 0 {
		return nil, errors.New("no A record found")
	}
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A, nil
		}
	}
	return nil, errors.New("no A record")
}

// resolveOverTun использует туннельный резолвер.
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

// Stop – no-op.
func (r *fixedResolver) Stop() {}
