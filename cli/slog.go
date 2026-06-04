package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"

	"github.com/muesli/termenv"
)

// prettyHandler is a slog.Handler that writes human-readable output:
//   - INFO: message and attrs only, no level label or timestamp
//   - WARN: "WARN" prefix (yellow when writing to a terminal)
//   - ERROR: "ERR " prefix (red when writing to a terminal)
//
// Colour detection (TTY, NO_COLOR, CLICOLOR) is delegated to termenv so the
// handler stays consistent with the rest of the CLI output. The styled level
// prefixes are precomputed: when colour is unavailable termenv emits the plain
// label with no escape codes.
type prettyHandler struct {
	w          io.Writer
	mu         sync.Mutex
	pre        []slog.Attr
	level      slog.Level
	errPrefix  string
	warnPrefix string
}

func newPrettyHandler(w io.Writer, level slog.Level) *prettyHandler {
	out := termenv.NewOutput(w)
	return &prettyHandler{
		w:          w,
		level:      level,
		errPrefix:  out.String("ERR ").Foreground(out.Color("#800000")).String(),
		warnPrefix: out.String("WARN").Foreground(out.Color("#808000")).String() + " ",
	}
}

func (h *prettyHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level
}

func (h *prettyHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	var sb strings.Builder

	switch {
	case r.Level >= slog.LevelError:
		sb.WriteString(h.errPrefix)
	case r.Level >= slog.LevelWarn:
		sb.WriteString(h.warnPrefix)
	}

	sb.WriteString(r.Message)

	for _, a := range h.pre {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
	}

	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&sb, " %s=%v", a.Key, a.Value)
		return true
	})

	sb.WriteByte('\n')
	_, err := h.w.Write([]byte(sb.String()))
	return err
}

func (h *prettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	pre := make([]slog.Attr, len(h.pre)+len(attrs))
	copy(pre, h.pre)
	copy(pre[len(h.pre):], attrs)
	return &prettyHandler{
		w:          h.w,
		level:      h.level,
		pre:        pre,
		errPrefix:  h.errPrefix,
		warnPrefix: h.warnPrefix,
	}
}

func (h *prettyHandler) WithGroup(_ string) slog.Handler {
	return h
}
