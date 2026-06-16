package wireproxy

import (
	"net"
	"testing"
	"time"

	"github.com/hashicorp/golang-lru/v2"
)

func TestFixedResolver_LRUCacheSize(t *testing.T) {
	// Создаём резолвер с размером кэша 2 и большим TTL
	resolver := NewFixedResolver(nil, false, time.Hour, 2)

	// Добавляем 3 записи напрямую в кэш (третья вытеснит первую)
	resolver.Cache.Add("a.com", net.IP{192, 0, 2, 1})
	resolver.Cache.Add("b.com", net.IP{192, 0, 2, 2})
	resolver.Cache.Add("c.com", net.IP{192, 0, 2, 3})

	// Проверяем, что a.com вытеснена
	if _, ok := resolver.Cache.Get("a.com"); ok {
		t.Error("expected a.com to be evicted")
	}
	if _, ok := resolver.Cache.Get("b.com"); !ok {
		t.Error("expected b.com to be present")
	}
	if _, ok := resolver.Cache.Get("c.com"); !ok {
		t.Error("expected c.com to be present")
	}
}

func TestFixedResolver_TTLExpiration(t *testing.T) {
	// Создаём резолвер с TTL 100ms и размером 10
	resolver := NewFixedResolver(nil, false, 100*time.Millisecond, 10)

	// Добавляем запись
	resolver.Cache.Add("test.com", net.IP{192, 0, 2, 1})

	// Сразу должна быть доступна
	if _, ok := resolver.Cache.Get("test.com"); !ok {
		t.Error("expected test.com to be present")
	}

	// Ждём истечения TTL
	time.Sleep(150 * time.Millisecond)

	// Должна быть удалена
	if _, ok := resolver.Cache.Get("test.com"); ok {
		t.Error("expected test.com to be expired and removed")
	}
}

func TestPingRecord_LRUCacheSize(t *testing.T) {
	// Создаём LRU-кэш размером 2
	cache, err := lru.New[string, uint64](2)
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// Добавляем 3 записи
	cache.Add("ip1", 100)
	cache.Add("ip2", 200)
	cache.Add("ip3", 300)

	// Проверяем, что ip1 вытеснена
	if _, ok := cache.Get("ip1"); ok {
		t.Error("expected ip1 to be evicted")
	}
	if val, ok := cache.Get("ip2"); !ok || val != 200 {
		t.Error("expected ip2 to be present with value 200")
	}
	if val, ok := cache.Get("ip3"); !ok || val != 300 {
		t.Error("expected ip3 to be present with value 300")
	}
}

// Проверяем, что PingRecord корректно инициализируется в VirtualTun
func TestVirtualTun_PingRecordInit(t *testing.T) {
	cache, _ := lru.New[string, uint64](5)
	vt := &VirtualTun{
		PingRecord: cache,
	}

	vt.PingRecord.Add("10.0.0.1", 12345)
	if val, ok := vt.PingRecord.Get("10.0.0.1"); !ok || val != 12345 {
		t.Errorf("expected 12345, got %v", val)
	}
}
