package wireproxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"github.com/miekg/dns"
)

// fixedResolver реализует socks5.NameResolver с LRU-кэшем и учётом TTL из DNS-ответа.
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

// Resolve выполняет DNS-запрос с учётом TTL.
func (r *fixedResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	r.mu.RLock()
	ip, ok := r.cache.Get(name)
	r.mu.RUnlock()
	if ok {
		return ctx, ip, nil
	}

	var ipNet net.IP
	var ttl time.Duration
	var err error

	if r.systemDNS {
		ipNet, ttl, err = r.resolveSystemDNS(ctx, name)
	} else {
		ipNet, ttl, err = r.resolveOverTun(ctx, name)
	}
	if err != nil {
		return ctx, nil, err
	}
	if ttl == 0 {
		ttl = r.defaultTTL
	}

	r.mu.Lock()
	// Используем AddWithTTL, если метод существует
	if lru, ok := r.cache.(interface {
		AddWithTTL(string, net.IP, time.Duration) bool
	}); ok {
		lru.AddWithTTL(name, ipNet, ttl)
	} else {
		r.cache.Add(name, ipNet)
	}
	r.mu.Unlock()
	return ctx, ipNet, nil
}

// resolveSystemDNS использует системный резолвер через DNS-запрос для получения TTL.
func (r *fixedResolver) resolveSystemDNS(ctx context.Context, name string) (net.IP, time.Duration, error) {
	c := new(dns.Client)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	m.RecursionDesired = true

	resp, _, err := c.ExchangeContext(ctx, m, "8.8.8.8:53")
	if err != nil {
		return nil, 0, err
	}
	if len(resp.Answer) == 0 {
		return nil, 0, errors.New("no A record found")
	}
	for _, ans := range resp.Answer {
		if a, ok := ans.(*dns.A); ok {
			return a.A, time.Duration(a.Header().Ttl) * time.Second, nil
		}
	}
	return nil, 0, errors.New("no A record")
}

// resolveOverTun использует туннельный резолвер (без TTL, fallback на defaultTTL).
func (r *fixedResolver) resolveOverTun(ctx context.Context, name string) (net.IP, time.Duration, error) {
	addrs, err := r.tnet.LookupContextHost(ctx, name)
	if err != nil || len(addrs) == 0 {
		return nil, 0, err
	}
	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return nil, 0, errors.New("failed to parse IP")
	}
	return ip, 0, nil
}

// Stop – no-op.
func (r *fixedResolver) Stop() {}
