package wireproxy

import "time"

// Глобальные таймауты для всех TCP-соединений
const (
    // IdleTimeout – время бездействия, после которого соединение принудительно закрывается
    IdleTimeout = 5 * time.Minute

    // DialTimeout – максимальное время на установку TCP-соединения
    DialTimeout = 10 * time.Second

    // ReadTimeout – таймаут на чтение данных из соединения
    ReadTimeout = 30 * time.Second

    // WriteTimeout – таймаут на запись данных в соединение
    WriteTimeout = 30 * time.Second

    // HTTPTimeout – общий таймаут для HTTP-запросов (не CONNECT)
    HTTPTimeout = 30 * time.Second
)
