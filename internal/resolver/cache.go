package resolver

import (
    "context"
    "net"
    "sync"
    "time"

    "github.com/things-go/go-socks5"
)

// CachedResolver implements socks5.Resolver with automatic cache cleanup.
type CachedResolver struct {
    upstream  socks5.Resolver
    cache     sync.Map
    ttl       time.Duration
    stopCh    chan struct{}
}

// NewCachedResolver creates a new resolver with cache TTL.
func NewCachedResolver(ttl time.Duration) *CachedResolver {
    r := &CachedResolver{
        upstream: socks5.DefaultResolver,
        ttl:      ttl,
        stopCh:   make(chan struct{}),
    }
    go r.cleanupLoop()
    return r
}

// Resolve implements the socks5.Resolver interface.
func (r *CachedResolver) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
    if val, ok := r.cache.Load(name); ok {
        entry := val.(cacheEntry)
        if time.Since(entry.timestamp) < r.ttl {
            return ctx, entry.ip, nil
        }
        r.cache.Delete(name)
    }

    newCtx, ip, err := r.upstream.Resolve(ctx, name)
    if err == nil && ip != nil {
        r.cache.Store(name, cacheEntry{ip: ip, timestamp: time.Now()})
    }
    return newCtx, ip, err
}

// cleanupLoop runs in background and cleans expired entries.
func (r *CachedResolver) cleanupLoop() {
    ticker := time.NewTicker(r.ttl / 2)
    defer ticker.Stop()
    for {
        select {
        case <-ticker.C:
            r.cache.Range(func(key, value interface{}) bool {
                if time.Since(value.(cacheEntry).timestamp) >= r.ttl {
                    r.cache.Delete(key)
                }
                return true
            })
        case <-r.stopCh:
            return
        }
    }
}

// Stop terminates the background cleanup goroutine.
func (r *CachedResolver) Stop() {
    close(r.stopCh)
}

type cacheEntry struct {
    ip        net.IP
    timestamp time.Time
}
