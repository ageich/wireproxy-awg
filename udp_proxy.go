package wireproxy

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// udpSession представляет сессию переадресации UDP (клиент -> удалённый хост)
type udpSession struct {
	remoteConn    net.Conn
	lastActive    time.Time
	closeChan     chan struct{}
	inactivityDur time.Duration
}

// UDPProxyTunnelConfig — структура с полями для управления кэшем
type UDPProxyTunnelConfig struct {
	BindAddress       string
	Target            string
	InactivityTimeout int
	mu                sync.RWMutex // защищает sessions
	sessions          *lru.Cache[string, *udpSession]
}

// SetCacheSize изменяет размер кэша сессий.
func (conf *UDPProxyTunnelConfig) SetCacheSize(newSize int) error {
	conf.mu.Lock()
	defer conf.mu.Unlock()
	if conf.sessions == nil {
		return nil
	}
	newCache, err := lru.NewWithEvict[string, *udpSession](newSize, func(key string, sess *udpSession) {
		_ = sess.remoteConn.Close()
		select {
		case <-sess.closeChan:
		default:
			close(sess.closeChan)
		}
	})
	if err != nil {
		return err
	}
	conf.sessions = newCache
	return nil
}

// SpawnUDPProxy реализует основную логику UDP-прокси с поддержкой graceful shutdown.
// Возвращает ошибку вместо вызова log.Fatal.
func (conf *UDPProxyTunnelConfig) SpawnUDPProxy(ctx context.Context, vt *VirtualTun) error {
	addr, err := net.ResolveUDPAddr("udp", conf.BindAddress)
	if err != nil {
		return fmt.Errorf("UDPProxyTunnelConfig: could not resolve bind address %s: %w", conf.BindAddress, err)
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("UDPProxyTunnelConfig: could not listen on %s: %w", conf.BindAddress, err)
	}
	defer listener.Close()

	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("UDP listener close goroutine panicked", "recover", r)
			}
		}()
		<-ctx.Done()
		listener.Close()
	}()

	Log.Info("UDPProxyTunnel listening", "bind", conf.BindAddress, "target", conf.Target)

	cacheSize := vt.UdpSessionCacheSize
	if cacheSize <= 0 {
		cacheSize = 500
	}

	inactivityDur := time.Duration(conf.InactivityTimeout) * time.Second

	sessions, err := lru.NewWithEvict[string, *udpSession](cacheSize,
		func(key string, sess *udpSession) {
			_ = sess.remoteConn.Close()
			select {
			case <-sess.closeChan:
			default:
				close(sess.closeChan)
			}
		})
	if err != nil {
		return fmt.Errorf("UDPProxyTunnel: failed to create LRU cache: %w", err)
	}
	conf.mu.Lock()
	conf.sessions = sessions
	conf.mu.Unlock()

	var sessionMu sync.RWMutex // позволяет параллельное чтение

	removeSession := func(src string, sess *udpSession) {
		sessionMu.Lock()
		defer sessionMu.Unlock()
		conf.mu.RLock()
		currentCache := conf.sessions
		conf.mu.RUnlock()
		if currentCache != nil {
			if existing, ok := currentCache.Get(src); ok && existing == sess {
				currentCache.Remove(src)
			}
		}
	}

	if conf.InactivityTimeout > 0 {
		go func() {
			defer func() {
				if r := recover(); r != nil {
					Log.Error("UDP inactivity timer goroutine panicked", "recover", r)
				}
			}()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now := time.Now()
					sessionMu.RLock()
					conf.mu.RLock()
					currentCache := conf.sessions
					conf.mu.RUnlock()
					if currentCache != nil {
						keys := currentCache.Keys()
						sessionMu.RUnlock()
						// Блокируем только на время удаления
						sessionMu.Lock()
						for _, key := range keys {
							if sess, ok := currentCache.Get(key); ok {
								if now.Sub(sess.lastActive) >= inactivityDur {
									Log.Info("UDPProxyTunnel: closing inactive session", "src", key)
									currentCache.Remove(key)
								}
							}
						}
						sessionMu.Unlock()
					} else {
						sessionMu.RUnlock()
					}
				}
			}
		}()
	}

	getOrCreateSession := func(srcAddr string) (*udpSession, error) {
		sessionMu.RLock()
		conf.mu.RLock()
		currentCache := conf.sessions
		conf.mu.RUnlock()
		if s, ok := currentCache.Get(srcAddr); ok {
			s.lastActive = time.Now()
			sessionMu.RUnlock()
			return s, nil
		}
		sessionMu.RUnlock()

		// Создаём новую сессию
		sessionMu.Lock()
		defer sessionMu.Unlock()
		// Double-check после получения блокировки
		conf.mu.RLock()
		currentCache = conf.sessions
		conf.mu.RUnlock()
		if s, ok := currentCache.Get(srcAddr); ok {
			s.lastActive = time.Now()
			return s, nil
		}

		remoteConn, err := vt.Tnet.Dial("udp", conf.Target)
		if err != nil {
			return nil, fmt.Errorf("UDPProxyTunnel: could not Dial(%s): %w", conf.Target, err)
		}

		s := &udpSession{
			remoteConn:    remoteConn,
			lastActive:    time.Now(),
			closeChan:     make(chan struct{}),
			inactivityDur: inactivityDur,
		}
		currentCache.Add(srcAddr, s)

		go conf.handleRemoteToLocal(ctx, listener, srcAddr, s, removeSession)
		return s, nil
	}

	// Основной цикл чтения из UDP с поддержкой контекста
	go func() {
		defer func() {
			if r := recover(); r != nil {
				Log.Error("UDP read loop goroutine panicked", "recover", r)
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			default:
				buf := GetBuffer()
				n, src, err := listener.ReadFromUDP(buf)
				if err != nil {
					PutBuffer(buf)
					select {
					case <-ctx.Done():
						return
					default:
						Log.Error("UDPProxyTunnel: error reading from UDP", "error", err)
						continue
					}
				}

				srcKey := src.String()
				s, err := getOrCreateSession(srcKey)
				if err != nil {
					Log.Error("UDPProxyTunnel: getOrCreateSession failed", "src", srcKey, "error", err)
					PutBuffer(buf)
					continue
				}

				s.lastActive = time.Now()
				_, err = s.remoteConn.Write(buf[:n])
				if err != nil {
					Log.Error("UDPProxyTunnel: could not write to remote", "target", conf.Target, "error", err)
				}
				PutBuffer(buf)
			}
		}
	}()

	<-ctx.Done()
	return nil
}

// handleRemoteToLocal читает данные из удалённого соединения и отправляет их обратно локальному клиенту
func (conf *UDPProxyTunnelConfig) handleRemoteToLocal(ctx context.Context, listener *net.UDPConn, srcAddr string, s *udpSession, removeSession func(string, *udpSession)) {
	defer func() {
		if r := recover(); r != nil {
			Log.Error("UDP handleRemoteToLocal panicked", "src", srcAddr, "recover", r)
		}
	}()
	defer func() {
		removeSession(srcAddr, s)
		_ = s.remoteConn.Close()
	}()

	buf := GetBuffer()
	defer PutBuffer(buf)

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closeChan:
			return
		default:
		}

		_ = s.remoteConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := s.remoteConn.Read(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				select {
				case <-s.closeChan:
					return
				default:
					continue
				}
			}
			Log.Error("UDPProxyTunnel: read error from remote", "src", srcAddr, "error", err)
			return
		}

		s.lastActive = time.Now()

		dstUDPAddr, err := net.ResolveUDPAddr("udp", srcAddr)
		if err != nil {
			Log.Error("UDPProxyTunnel: cannot resolve local address", "src", srcAddr, "error", err)
			return
		}

		_, err = listener.WriteToUDP(buf[:n], dstUDPAddr)
		if err != nil {
			Log.Error("UDPProxyTunnel: cannot write to local", "src", srcAddr, "error", err)
			return
		}
	}
}
