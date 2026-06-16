package wireproxy

import (
	"net"
	"sync"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

// mockConn — заглушка для net.Conn
type mockConn struct {
	closed bool
}

func (m *mockConn) Read(b []byte) (n int, err error)   { return 0, nil }
func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { m.closed = true; return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestUDPProxy_LRUSessionEviction(t *testing.T) {
	var evictedKeys []string
	var mu sync.Mutex

	// Создаём LRU-кэш размером 2 с колбэком
	cache, err := lru.NewWithEvict[string, *udpSession](2, func(key string, sess *udpSession) {
		mu.Lock()
		evictedKeys = append(evictedKeys, key)
		mu.Unlock()
		// Закрываем соединение (mock)
		_ = sess.remoteConn.Close()
	})
	if err != nil {
		t.Fatalf("failed to create LRU: %v", err)
	}

	// Создаём три сессии с mock-соединениями
	sess1 := &udpSession{remoteConn: &mockConn{}, closeChan: make(chan struct{})}
	sess2 := &udpSession{remoteConn: &mockConn{}, closeChan: make(chan struct{})}
	sess3 := &udpSession{remoteConn: &mockConn{}, closeChan: make(chan struct{})}

	cache.Add("addr1", sess1)
	cache.Add("addr2", sess2)
	cache.Add("addr3", sess3) // вытеснит addr1

	// Проверяем, что addr1 больше нет
	if _, ok := cache.Get("addr1"); ok {
		t.Error("addr1 should have been evicted")
	}
	// Проверяем, что колбэк вызван для addr1
	mu.Lock()
	if len(evictedKeys) != 1 || evictedKeys[0] != "addr1" {
		t.Errorf("expected eviction of addr1, got %v", evictedKeys)
	}
	mu.Unlock()
}

func TestUDPProxy_SessionReuse(t *testing.T) {
	cache, _ := lru.New[string, *udpSession](2)

	sess := &udpSession{remoteConn: &mockConn{}, closeChan: make(chan struct{})}
	cache.Add("addr1", sess)

	// Получаем сессию
	if got, ok := cache.Get("addr1"); !ok || got != sess {
		t.Error("failed to retrieve existing session")
	}

	// Добавляем ещё одну сессию, убеждаемся, что addr1 остаётся
	cache.Add("addr2", &udpSession{remoteConn: &mockConn{}, closeChan: make(chan struct{})})
	if _, ok := cache.Get("addr1"); !ok {
		t.Error("addr1 should still be present")
	}
}
