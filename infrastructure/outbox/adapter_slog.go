package outbox

import (
	"io"
	"log/slog"
	"os"

	loggeroutbox "github.com/assurrussa/outbox/outbox/logger"
)

type SlogAdapter = loggeroutbox.SlogAdapter

func init() {
	loggeroutbox.LogLevel.Set(slog.LevelInfo)
}

func WrapNamed(logger Logger, names ...string) *SlogAdapter {
	return loggeroutbox.WrapNamed(logger, names...)
}

func WrapWithAttrs(logger Logger, attrs ...slog.Attr) *SlogAdapter {
	return loggeroutbox.WrapWithAttrs(logger, attrs...)
}

func Default() *SlogAdapter {
	return DefaultJSONWithWriter(os.Stdout)
}

func DefaultText() *SlogAdapter {
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &loggeroutbox.LogLevel})
	return NewLogger(handler)
}

// Discard empty logger.
func Discard() *SlogAdapter {
	return DefaultJSONWithWriter(io.Discard)
}

func DefaultJSONWithWriter(w io.Writer) *SlogAdapter {
	handler := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: &loggeroutbox.LogLevel})
	return NewLogger(handler)
}

// Error returns an Attr for the error value.
func Error(err error) slog.Attr {
	return loggeroutbox.Error(err)
}

// NewLogger builds a default logger from config.
func NewLogger(handler slog.Handler) *SlogAdapter {
	return loggeroutbox.NewLogger(handler)
}
