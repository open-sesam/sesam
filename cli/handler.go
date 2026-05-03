package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

const (
	ansiReset  = "\033[0m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
)

// prettyHandler is a slog.Handler that writes human-readable output:
//   - INFO: message and attrs only, no level label or timestamp
//   - WARN: "WARN" prefix (yellow when writing to a terminal)
//   - ERROR: "ERR " prefix (red when writing to a terminal)
type prettyHandler struct {
	w     io.Writer
	mu    sync.Mutex
	pre   []slog.Attr
	level slog.Level
	color bool
}

func newPrettyHandler(w io.Writer, level slog.Level) *prettyHandler {
	color := false
	if f, ok := w.(*os.File); ok {
		//nolint:gosec
		color = term.IsTerminal(int(f.Fd()))
	}
	return &prettyHandler{w: w, level: level, color: color}
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
		if h.color {
			sb.WriteString(ansiRed + "ERR " + ansiReset)
		} else {
			sb.WriteString("ERR ")
		}
	case r.Level >= slog.LevelWarn:
		if h.color {
			sb.WriteString(ansiYellow + "WARN" + ansiReset + " ")
		} else {
			sb.WriteString("WARN ")
		}
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
	return &prettyHandler{w: h.w, level: h.level, pre: pre, color: h.color}
}

func (h *prettyHandler) WithGroup(_ string) slog.Handler {
	return h
}
