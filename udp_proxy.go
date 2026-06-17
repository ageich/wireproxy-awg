package wireproxy

import (
	"fmt"
	"log"
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

// UDPProxyTunnelConfig расширена для поддержки динамического изменения размера
type UDPProxyTunnelConfig struct {
	BindAddress       string
	Target            string
	InactivityTimeout int
	// для динамического изменения
	sessions *lru.Cache[string, *udpSession]
	mu       sync.Mutex
}

// SetCacheSize изменяет размер кэша сессий.
func (conf *UDPProxyTunnelConfig) SetCacheSize(newSize int) error {
	conf.mu.Lock()
	defer conf.mu.Unlock()
	if conf.sessions == nil {
		return nil // ещё не создан
	}
	// Создаём новый кэш с новым размером и таким же evict-колбэком
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
	// Заменяем старый кэш новым. Старые сессии продолжат жить до таймаута.
	conf.sessions = newCache
	return nil
}

// SpawnUDPProxy реализует основную логику UDP-прокси.
// Вынесена из SpawnRoutine для возможности переиспользования.
func (conf *UDPProxyTunnelConfig) SpawnUDPProxy(vt *VirtualTun) {
	addr, err := net.ResolveUDPAddr("udp", conf.BindAddress)
	if err != nil {
		log.Fatalf("UDPProxyTunnelConfig: could not resolve bind address %s: %v", conf.BindAddress, err)
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDPProxyTunnelConfig: could not listen on %s: %v", conf.BindAddress, err)
	}
	log.Printf("UDPProxyTunnel listening on %s, forwarding to %s", conf.BindAddress, conf.Target)

	cacheSize := vt.UdpSessionCacheSize
	if cacheSize <= 0 {
		cacheSize = 500
	}

	inactivityDur := time.Duration(conf.InactivityTimeout) * time.Second

	// Создаём LRU-кэш и сохраняем в конфиг
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
		log.Fatalf("UDPProxyTunnel: failed to create LRU cache: %v", err)
	}
	conf.mu.Lock()
	conf.sessions = sessions
	conf.mu.Unlock()

	var sessionMu sync.Mutex

	closeSessionChan := func(sess *udpSession) {
		select {
		case <-sess.closeChan:
		default:
			close(sess.closeChan)
		}
	}

	removeSession := func(src string, sess *udpSession) {
		sessionMu.Lock()
		defer sessionMu.Unlock()
		// Используем актуальный кэш из конфига
		conf.mu.Lock()
		currentCache := conf.sessions
		conf.mu.Unlock()
		if current, ok := currentCache.Get(src); ok && current == sess {
			currentCache.Remove(src)
		}
	}

	if conf.InactivityTimeout > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				sessionMu.Lock()
				conf.mu.Lock()
				currentCache := conf.sessions
				conf.mu.Unlock()
				if currentCache != nil {
					for _, key := range currentCache.Keys() {
						if sess, ok := currentCache.Get(key); ok {
							if now.Sub(sess.lastActive) >= inactivityDur {
								log.Printf("UDPProxyTunnel: closing inactive session for %s", key)
								currentCache.Remove(key)
							}
						}
					}
				}
				sessionMu.Unlock()
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

		go conf.handleRemoteToLocal(listener, srcAddr, s, removeSession)
		return s, nil
	}

	go func() {
		for {
			buf := GetBuffer()
			n, src, err := listener.ReadFromUDP(buf)
			if err != nil {
				PutBuffer(buf)
				log.Printf("UDPProxyTunnel: error reading from UDP: %v", err)
				return
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
	}()
}

// SpawnRoutine реализует интерфейс RoutineSpawner
func (conf *UDPProxyTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	conf.SpawnUDPProxy(vt)
}

// handleRemoteToLocal читает данные из удалённого соединения и отправляет их обратно локальному клиенту
func (conf *UDPProxyTunnelConfig) handleRemoteToLocal(listener *net.UDPConn, srcAddr string, s *udpSession, removeSession func(string, *udpSession)) {
	defer func() {
		removeSession(srcAddr, s)
		_ = s.remoteConn.Close()
	}()

	buf := GetBuffer()
	defer PutBuffer(buf)

	for {
		select {
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
