package wireproxy

import (
	"context"
	"fmt"
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

// UDPProxyTunnelConfig — полная структура с полями для управления кэшем
type UDPProxyTunnelConfig struct {
	BindAddress       string
	Target            string
	InactivityTimeout int
	mu                sync.Mutex
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

	// Закрываем слушатель при отмене контекста
	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	errorLogger.Printf("UDPProxyTunnel listening on %s, forwarding to %s", conf.BindAddress, conf.Target)

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

	var sessionMu sync.Mutex

	removeSession := func(src string, sess *udpSession) {
		sessionMu.Lock()
		defer sessionMu.Unlock()
		conf.mu.Lock()
		currentCache := conf.sessions
		conf.mu.Unlock()
		if currentCache != nil {
			if existing, ok := currentCache.Get(src); ok && existing == sess {
				currentCache.Remove(src)
			}
		}
	}

	if conf.InactivityTimeout > 0 {
		go func() {
			// Увеличиваем интервал проверки с 10 до 30 секунд для снижения нагрузки
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					now := time.Now()
					sessionMu.Lock()
					conf.mu.Lock()
					currentCache := conf.sessions
					conf.mu.Unlock()
					if currentCache != nil {
						for _, key := range currentCache.Keys() {
							if sess, ok := currentCache.Get(key); ok {
								if now.Sub(sess.lastActive) >= inactivityDur {
									errorLogger.Printf("UDPProxyTunnel: closing inactive session for %s", key)
									currentCache.Remove(key)
								}
							}
						}
					}
					sessionMu.Unlock()
				}
			}
		}()
	}

	getOrCreateSession := func(srcAddr string) (*udpSession, error) {
		sessionMu.Lock()
		defer sessionMu.Unlock()

		conf.mu.Lock()
		currentCache := conf.sessions
		conf.mu.Unlock()

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
						errorLogger.Printf("UDPProxyTunnel: error reading from UDP: %v", err)
						continue
					}
				}

				srcKey := src.String()
				s, err := getOrCreateSession(srcKey)
				if err != nil {
					errorLogger.Printf("UDPProxyTunnel: getOrCreateSession failed for %s: %v", srcKey, err)
					PutBuffer(buf)
					continue
				}

				s.lastActive = time.Now()
				_, err = s.remoteConn.Write(buf[:n])
				if err != nil {
					errorLogger.Printf("UDPProxyTunnel: could not write to remote (%s): %v", conf.Target, err)
				}
				PutBuffer(buf)
			}
		}
	}()

	// Ожидаем отмены контекста (чтобы горутина не завершилась сразу)
	<-ctx.Done()
	return nil
}

// handleRemoteToLocal читает данные из удалённого соединения и отправляет их обратно локальному клиенту
func (conf *UDPProxyTunnelConfig) handleRemoteToLocal(ctx context.Context, listener *net.UDPConn, srcAddr string, s *udpSession, removeSession func(string, *udpSession)) {
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
			errorLogger.Printf("UDPProxyTunnel: read error from remote: %v", err)
			return
		}

		s.lastActive = time.Now()

		dstUDPAddr, err := net.ResolveUDPAddr("udp", srcAddr)
		if err != nil {
			errorLogger.Printf("UDPProxyTunnel: cannot resolve local address %s: %v", srcAddr, err)
			return
		}

		_, err = listener.WriteToUDP(buf[:n], dstUDPAddr)
		if err != nil {
			errorLogger.Printf("UDPProxyTunnel: cannot write to local %s: %v", srcAddr, err)
			return
		}
	}
}
