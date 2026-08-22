// Package logging adapts structured slog records to Zabbix logging.
package logging

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strings"
)

type zabbixLogger interface {
	Infof(format string, args ...any)
	Critf(format string, args ...any)
	Errf(format string, args ...any)
	Warningf(format string, args ...any)
	Debugf(format string, args ...any)
	Tracef(format string, args ...any)
}

type handlerOp struct {
	attrs []slog.Attr
	group string
}

// ZabbixHandler adapts slog records to a Zabbix logger.
type ZabbixHandler struct {
	logger zabbixLogger
	ops    []handlerOp
}

// NewZabbixHandler returns a Zabbix-backed slog handler.
func NewZabbixHandler(logger zabbixLogger) *ZabbixHandler {
	return &ZabbixHandler{
		logger: logger,
		ops:    nil,
	}
}

// Enabled reports whether records are handled.
func (h *ZabbixHandler) Enabled(_ context.Context, _ slog.Level) bool {
	return true
}

// Handle formats and forwards a slog record to Zabbix logging.
func (h *ZabbixHandler) Handle(ctx context.Context, record slog.Record) error {
	var buf bytes.Buffer

	var handler slog.Handler = slog.NewJSONHandler(
		&buf,
		&slog.HandlerOptions{
			Level:     slog.LevelDebug,
			AddSource: false,
			ReplaceAttr: func(groups []string, attr slog.Attr) slog.Attr {
				if len(groups) == 0 {
					switch attr.Key {
					case slog.TimeKey, slog.LevelKey:
						return slog.Attr{Key: "", Value: slog.Value{}}
					}
				}

				return attr
			},
		},
	)

	for _, operation := range h.ops {
		if operation.group != "" {
			handler = handler.WithGroup(operation.group)

			continue
		}

		handler = handler.WithAttrs(operation.attrs)
	}

	err := handler.Handle(ctx, record)
	if err != nil {
		return fmt.Errorf("handle slog record: %w", err)
	}

	message := strings.TrimSpace(buf.String())

	h.log(record.Level, message)

	return nil
}

// WithAttrs adds attributes to the handler.
func (h *ZabbixHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}

	clone := *h
	clone.ops = append([]handlerOp(nil), h.ops...)
	clone.ops = append(clone.ops, handlerOp{
		attrs: append([]slog.Attr(nil), attrs...),
		group: "",
	})

	return &clone
}

// WithGroup nests subsequent attributes.
func (h *ZabbixHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}

	clone := *h
	clone.ops = append([]handlerOp(nil), h.ops...)
	clone.ops = append(clone.ops, handlerOp{
		attrs: nil,
		group: name,
	})

	return &clone
}

func (h *ZabbixHandler) log(level slog.Level, message string) {
	switch {
	case level >= slog.LevelError:
		h.logger.Errf("%s", message)
	case level >= slog.LevelWarn:
		h.logger.Warningf("%s", message)
	case level >= slog.LevelInfo:
		h.logger.Infof("%s", message)
	case level >= slog.LevelDebug:
		h.logger.Debugf("%s", message)
	default:
		h.logger.Tracef("%s", message)
	}
}
