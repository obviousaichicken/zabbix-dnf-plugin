package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"

	"golang.zabbix.com/sdk/plugin"
)

type timeoutProvider struct {
	timeout int
}

func (timeoutProvider) ClientID() uint64 {
	return 0
}

func (timeoutProvider) ItemID() uint64 {
	return 0
}

func (timeoutProvider) Output() plugin.ResultWriter { //nolint:ireturn
	return nil
}

func (timeoutProvider) Meta() *plugin.Meta {
	return nil
}

func (timeoutProvider) GlobalRegexp() plugin.RegexpMatcher { //nolint:ireturn
	return nil
}

func (p timeoutProvider) Timeout() int {
	return p.timeout
}

func (timeoutProvider) Delay() string {
	return ""
}

func TestRequestTimeout(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configured time.Duration
		provider   plugin.ContextProvider
		want       time.Duration
	}{
		{
			name:       "request timeout overrides configured timeout",
			configured: 30 * time.Second,
			provider:   timeoutProvider{timeout: 90},
			want:       90 * time.Second,
		},
		{
			name:       "configured timeout used without request timeout",
			configured: 45 * time.Second,
			provider:   timeoutProvider{timeout: 0},
			want:       45 * time.Second,
		},
		{
			name:       "default used without positive timeout",
			configured: 0,
			provider:   nil,
			want:       defaultTimeout,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got := requestTimeout(testCase.configured, testCase.provider)
			if got != testCase.want {
				t.Fatalf("requestTimeout() = %s, want %s", got, testCase.want)
			}
		})
	}
}

func TestPluginConfigure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		global *plugin.GlobalOptions
		want   time.Duration
	}{
		{name: "nil options", global: nil, want: defaultTimeout},
		{
			name:   "non-positive timeout",
			global: &plugin.GlobalOptions{Timeout: -1},
			want:   defaultTimeout,
		},
		{
			name:   "configured timeout",
			global: &plugin.GlobalOptions{Timeout: 45},
			want:   45 * time.Second,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			p := new(Plugin)
			p.Configure(testCase.global, nil)

			p.lifecycleMu.Lock()
			got := p.timeout
			p.lifecycleMu.Unlock()
			if got != testCase.want {
				t.Fatalf("Plugin.timeout = %s, want %s", got, testCase.want)
			}
		})
	}
}

func TestPluginStopCancelsAndWaitsForActiveExports(t *testing.T) {
	t.Parallel()

	p := new(Plugin)
	p.Start()

	ctx, finish, err := p.beginExport(nil)
	if err != nil {
		t.Fatalf("beginExport() error = %v", err)
	}

	exportDone := make(chan struct{})
	go func() {
		<-ctx.Done()
		finish()
		close(exportDone)
	}()

	p.Stop()

	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatalf("export context error = %v, want context canceled", ctx.Err())
	}
	select {
	case <-exportDone:
	default:
		t.Fatal("Stop() returned before the active export finished")
	}

	_, _, err = p.beginExport(nil)
	if !errors.Is(err, errPluginStopping) {
		t.Fatalf("beginExport() after Stop() error = %v, want %v", err, errPluginStopping)
	}
}

func TestPluginConfigureWhileExportsBegin(t *testing.T) {
	t.Parallel()

	p := new(Plugin)
	p.Start()

	configured := make(chan struct{})
	go func() {
		defer close(configured)
		for range 1_000 {
			p.Configure(&plugin.GlobalOptions{Timeout: 45}, nil)
		}
	}()

	for range 1_000 {
		_, finish, err := p.beginExport(nil)
		if err != nil {
			t.Fatalf("beginExport() error = %v", err)
		}
		finish()
	}
	<-configured
	p.Stop()
}

func TestPluginValidate(t *testing.T) {
	t.Parallel()

	p := new(Plugin)
	if err := p.Validate(nil); err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
}

func TestPluginExportRejectsInvalidRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		params  []string
		wantErr error
	}{
		{
			name:    "unsupported key",
			key:     "unsupported",
			wantErr: errUnsupportedItemKey,
		},
		{
			name:    "item key parameters",
			key:     metricGet,
			params:  []string{"unexpected"},
			wantErr: errItemKeyParameters,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			p := new(Plugin)
			_, err := p.Export(testCase.key, testCase.params, nil)
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("Export() error = %v, want %v", err, testCase.wantErr)
			}
		})
	}
}

func TestLogFailureDoesNotLogDNFStderr(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	p := new(Plugin)
	p.logger = slog.New(slog.NewJSONHandler(&output, nil))

	p.logFailure("updates", &dnf.CommandError{
		Command:    "/usr/bin/dnf repoquery",
		ExitStatus: 1,
		Stderr:     "raw stderr marker",
		Err:        context.Canceled,
	})

	if strings.Contains(output.String(), "raw stderr marker") {
		t.Fatalf("log contains raw command stderr: %s", output.String())
	}
}
