package wireproxy

import (
	"fmt"
	"log/slog"
	"os"
)

var Log *slog.Logger

func init() {
	Log = slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// SetLogLevel устанавливает уровень логирования.
func SetLogLevel(level string) error {
	var l slog.Level
	switch level {
	case "debug":
		l = slog.LevelDebug
	case "info":
		l = slog.LevelInfo
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		return fmt.Errorf("unknown log level: %s", level)
	}
	Log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: l}))
	return nil
}
