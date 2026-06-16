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

// SpawnRoutine реализует интерфейс RoutineSpawner.
// Запускает UDP-прокси с ограниченным LRU-кэшем сессий.
// Размер кэша задаётся в vt.UdpSessionCacheSize (по умолчанию 500).
func (conf *UDPProxyTunnelConfig) SpawnRoutine(vt *VirtualTun) {
	addr, err := net.ResolveUDPAddr("udp", conf.BindAddress)
	if err != nil {
		log.Fatalf("UDPProxyTunnelConfig: could not resolve bind address %s: %v", conf.BindAddress, err)
	}

	listener, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("UDPProxyTunnelConfig: could not listen on %s: %v", conf.BindAddress, err)
	}
	log.Printf("UDPProxyTunnel listening on %s, forwarding to %s", conf.BindAddress, conf.Target)

	// Определяем размер кэша (если не задан, используем 500)
	cacheSize := vt.UdpSessionCacheSize
	if cacheSize <= 0 {
		cacheSize = 500
	}

	inactivityDur := time.Duration(conf.InactivityTimeout) * time.Second

	// Создаём LRU-кэш сессий с колбэком при вытеснении
	sessions, err := lru.NewWithEvict[string, *udpSession](cacheSize,
		func(key string, sess *udpSession) {
			// Закрываем соединение и канал при вытеснении из кэша
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

	var sessionMu sync.Mutex // защищает операции с LRU

	// Безопасно закрывает канал сессии (игнорирует, если уже закрыт)
	closeSessionChan := func(sess *udpSession) {
		select {
		case <-sess.closeChan:
		default:
			close(sess.closeChan)
		}
	}

	// Удаляет сессию из LRU и закрывает её (вызывается при таймауте или завершении)
	removeSession := func(src string, sess *udpSession) {
		sessionMu.Lock()
		defer sessionMu.Unlock()
		if current, ok := sessions.Get(src); ok && current == sess {
			sessions.Remove(src) // вызовет колбэк, который закроет ресурсы
		}
	}

	// Периодически проверяем неактивные сессии (если задан InactivityTimeout)
	if conf.InactivityTimeout > 0 {
		go func() {
			ticker := time.NewTicker(10 * time.Second)
			defer ticker.Stop()
			for range ticker.C {
				now := time.Now()
				sessionMu.Lock()
				for _, key := range sessions.Keys() {
					if sess, ok := sessions.Get(key); ok {
						if now.Sub(sess.lastActive) >= inactivityDur {
							log.Printf("UDPProxyTunnel: closing inactive session for %s", key)
							// Удаляем из кэша (колбэк закроет ресурсы)
							sessions.Remove(key)
						}
					}
				}
				sessionMu.Unlock()
			}
		}()
	}

	// Создаёт или возвращает существующую сессию
	getOrCreateSession := func(srcAddr string) (*udpSession, error) {
		sessionMu.Lock()
		defer sessionMu.Unlock()

		if s, ok := sessions.Get(srcAddr); ok {
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
		sessions.Add(srcAddr, s)

		// Запускаем обработчик трафика из удалённой стороны в локальную
		go conf.handleRemoteToLocal(listener, srcAddr, s, removeSession)
		return s, nil
	}

	// Основной цикл: читаем от локального клиента и шлём в удалённый endpoint
	go func() {
		for {
			buf := make([]byte, 64*1024)
			n, src, err := listener.ReadFromUDP(buf)
			if err != nil {
				log.Printf("UDPProxyTunnel: error reading from UDP: %v", err)
				return
			}

			srcKey := src.String()
			s, err := getOrCreateSession(srcKey)
			if err != nil {
				errorLogger.Printf("UDPProxyTunnel: getOrCreateSession failed for %s: %v", srcKey, err)
				continue
			}

			s.lastActive = time.Now()
			_, err = s.remoteConn.Write(buf[:n])
			if err != nil {
				errorLogger.Printf("UDPProxyTunnel: could not write to remote (%s): %v", conf.Target, err)
			}
		}
	}()
}

// handleRemoteToLocal читает данные из удалённого соединения и отправляет их обратно локальному клиенту
func (conf *UDPProxyTunnelConfig) handleRemoteToLocal(listener *net.UDPConn, srcAddr string, s *udpSession, removeSession func(string, *udpSession)) {
	defer func() {
		removeSession(srcAddr, s) // удаляем сессию из кэша (если она ещё там)
		_ = s.remoteConn.Close()
	}()
	buf := make([]byte, 64*1024)

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
				// При таймауте проверяем, не закрыт ли канал
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
