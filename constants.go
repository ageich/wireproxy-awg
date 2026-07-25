package wireproxy

import "time"

// Глобальные таймауты для всех TCP-соединений
// Увеличены для повышения стабильности при медленных или нестабильных сетях,
// но IdleTimeout уменьшен для быстрого освобождения горутин в SOCKS5.
const (
    // IdleTimeout – время бездействия, после которого соединение принудительно закрывается
    // Уменьшено с 10 до 3 минут для более быстрой очистки висячих горутин.
    IdleTimeout = 3 * time.Minute // было 10 минут

    // DialTimeout – максимальное время на установку TCP-соединения
    DialTimeout = 15 * time.Second // было 10 секунд

    // ReadTimeout – таймаут на чтение данных из соединения
    ReadTimeout = 60 * time.Second // было 30 секунд

    // WriteTimeout – таймаут на запись данных в соединение
    WriteTimeout = 60 * time.Second // было 30 секунд

    // HTTPTimeout – общий таймаут для HTTP-запросов (не CONNECT)
    HTTPTimeout = 60 * time.Second // было 30 секунд
)
