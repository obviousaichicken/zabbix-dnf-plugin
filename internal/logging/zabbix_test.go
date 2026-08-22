package logging_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/logging"
)

type logEntry struct {
	level   string
	message string
}

type fakeZabbixLogger struct {
	entries []logEntry
}

func (l *fakeZabbixLogger) Infof(format string, args ...any) {
	l.addf("info", format, args...)
}

func (l *fakeZabbixLogger) Critf(format string, args ...any) {
	l.addf("critical", format, args...)
}

func (l *fakeZabbixLogger) Errf(format string, args ...any) {
	l.addf("error", format, args...)
}

func (l *fakeZabbixLogger) Warningf(format string, args ...any) {
	l.addf("warning", format, args...)
}

func (l *fakeZabbixLogger) Debugf(format string, args ...any) {
	l.addf("debug", format, args...)
}

func (l *fakeZabbixLogger) Tracef(format string, args ...any) {
	l.addf("trace", format, args...)
}

func (l *fakeZabbixLogger) addf(
	level string,
	format string,
	args ...any,
) {
	l.entries = append(l.entries, logEntry{
		level:   level,
		message: fmt.Sprintf(format, args...),
	})
}

func TestZabbixHandlerPreservesGroups(t *testing.T) {
	t.Parallel()

	target := &fakeZabbixLogger{entries: nil}

	logger := slog.New(logging.NewZabbixHandler(target)).
		With("component", "dnf").
		WithGroup("repository").
		With("id", "updates").
		WithGroup("package")

	logger.Info(
		"update found",
		"name", "libei",
		"version", "1.6.0",
	)

	if len(target.entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(target.entries))
	}

	var payload map[string]any

	err := json.Unmarshal(
		[]byte(target.entries[0].message),
		&payload,
	)
	if err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if payload["component"] != "dnf" {
		t.Fatalf("component = %v, want dnf", payload["component"])
	}

	repository, repositoryOK := payload["repository"].(map[string]any)
	if !repositoryOK {
		t.Fatalf("repository = %#v, want object", payload["repository"])
	}

	if repository["id"] != "updates" {
		t.Fatalf("repository.id = %v, want updates", repository["id"])
	}

	pkg, packageOK := repository["package"].(map[string]any)
	if !packageOK {
		t.Fatalf("package = %#v, want object", repository["package"])
	}

	if pkg["name"] != "libei" {
		t.Fatalf("package.name = %v, want libei", pkg["name"])
	}

	if pkg["version"] != "1.6.0" {
		t.Fatalf(
			"package.version = %v, want 1.6.0",
			pkg["version"],
		)
	}
}

func TestZabbixHandlerMapsLevels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		level     slog.Level
		wantLevel string
	}{
		{"trace", slog.LevelDebug - 4, "trace"},
		{"debug", slog.LevelDebug, "debug"},
		{"info", slog.LevelInfo, "info"},
		{"warning", slog.LevelWarn, "warning"},
		{"error", slog.LevelError, "error"},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			target := &fakeZabbixLogger{entries: nil}
			logger := slog.New(logging.NewZabbixHandler(target))

			logger.Log(
				context.Background(),
				testCase.level,
				"test",
			)

			if len(target.entries) != 1 {
				t.Fatalf(
					"got %d entries, want 1",
					len(target.entries),
				)
			}

			if target.entries[0].level != testCase.wantLevel {
				t.Fatalf(
					"level = %q, want %q",
					target.entries[0].level,
					testCase.wantLevel,
				)
			}
		})
	}
}

func TestZabbixHandlerProducesStructuredJSON(t *testing.T) {
	t.Parallel()

	target := &fakeZabbixLogger{entries: nil}
	logger := slog.New(logging.NewZabbixHandler(target))

	logger.Info(
		"collection completed",
		"repositories", 13,
		"updates", 5,
	)

	var payload map[string]any

	err := json.Unmarshal(
		[]byte(target.entries[0].message),
		&payload,
	)
	if err != nil {
		t.Fatalf("decode JSON: %v", err)
	}

	if payload["msg"] != "collection completed" {
		t.Fatalf("msg = %v", payload["msg"])
	}

	if payload["repositories"] != float64(13) {
		t.Fatalf("repositories = %v", payload["repositories"])
	}

	if payload["updates"] != float64(5) {
		t.Fatalf("updates = %v", payload["updates"])
	}

	if _, exists := payload["time"]; exists {
		t.Fatal("unexpected time field")
	}

	if _, exists := payload["level"]; exists {
		t.Fatal("unexpected level field")
	}
}
