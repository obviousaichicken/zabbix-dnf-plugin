package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/results"

	"golang.zabbix.com/sdk/plugin"
)

const (
	defaultTimeout  = 30 * time.Second
	maxPayloadBytes = 8 << 20
)

var (
	_ plugin.Exporter     = (*Plugin)(nil)
	_ plugin.Configurator = (*Plugin)(nil)
	_ plugin.Runner       = (*Plugin)(nil)

	errUnsupportedItemKey = errors.New("unsupported item key")
	errItemKeyParameters  = errors.New("item key does not accept parameters")
	errPayloadTooLarge    = errors.New("result payload too large")
	errPluginStopping     = errors.New("plugin is stopping")
)

type Plugin struct {
	plugin.Base

	runner  command.Runner
	logger  *slog.Logger
	timeout time.Duration

	lifecycleMu sync.Mutex
	stop        chan struct{}
	stopping    bool
	exports     sync.WaitGroup
}

func (p *Plugin) Configure(global *plugin.GlobalOptions, _ any) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	if global == nil || global.Timeout <= 0 {
		p.timeout = defaultTimeout

		return
	}

	p.timeout = time.Duration(global.Timeout) * time.Second
}

func (*Plugin) Validate(_ any) error {
	return nil
}

func (p *Plugin) Start() {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	if p.stop == nil {
		p.stop = make(chan struct{})
	}
}

func (p *Plugin) Stop() {
	p.lifecycleMu.Lock()
	if !p.stopping {
		p.stopping = true
		if p.stop == nil {
			p.stop = make(chan struct{})
		}
		close(p.stop)
	}
	p.lifecycleMu.Unlock()

	p.exports.Wait()
}

func (p *Plugin) Export(
	key string,
	params []string,
	provider plugin.ContextProvider,
) (any, error) {
	if key != metricGet {
		return nil, fmt.Errorf("%w %q", errUnsupportedItemKey, key)
	}

	if len(params) != 0 {
		return nil, fmt.Errorf("%w: %s", errItemKeyParameters, key)
	}

	ctx, finish, err := p.beginExport(provider)
	if err != nil {
		return nil, err
	}
	defer finish()

	started := time.Now()

	payload, err := p.collect(ctx)
	if err != nil {
		return nil, err
	}
	payload.Collection.DurationMS = time.Since(started).Milliseconds()

	data, err := json.Marshal(payload)
	if err != nil {
		p.logFailure("encoding", err)

		return nil, fmt.Errorf("marshal result: %w", err)
	}

	if len(data) > maxPayloadBytes {
		err = fmt.Errorf(
			"%w: %d bytes, maximum is %d",
			errPayloadTooLarge,
			len(data),
			maxPayloadBytes,
		)
		p.logFailure("encoding", err)

		return nil, err
	}

	p.logger.Info(
		"collection completed",
		"repositories", payload.Summary.Repositories,
		"updates", payload.Summary.Updates,
		"reboot_pending", payload.Summary.RebootPending,
		"duration_ms", payload.Collection.DurationMS,
	)

	return string(data), nil
}

func (p *Plugin) beginExport(
	provider plugin.ContextProvider,
) (context.Context, func(), error) {
	p.lifecycleMu.Lock()
	if p.stopping {
		p.lifecycleMu.Unlock()

		return nil, nil, errPluginStopping
	}
	if p.stop == nil {
		p.stop = make(chan struct{})
	}

	stop := p.stop
	timeout := requestTimeout(p.timeout, provider)
	p.exports.Add(1)
	p.lifecycleMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, func() {
		cancel()
		p.exports.Done()
	}, nil
}

func requestTimeout(
	configured time.Duration,
	provider plugin.ContextProvider,
) time.Duration {
	if provider != nil && provider.Timeout() > 0 {
		return time.Duration(provider.Timeout()) * time.Second
	}

	if configured > 0 {
		return configured
	}

	return defaultTimeout
}

func (p *Plugin) collect(ctx context.Context) (results.Payload, error) {
	client, err := dnf.New(p.runner)
	if err != nil {
		p.logFailure("initialization", err)

		return results.Payload{}, fmt.Errorf("initialize DNF: %w", err)
	}

	repositories, err := client.Repositories(ctx)
	if err != nil {
		p.logFailure("repositories", err)

		return results.Payload{}, fmt.Errorf("collect repositories: %w", err)
	}

	updates, err := client.Updates(ctx)
	if err != nil {
		p.logFailure("updates", err)

		return results.Payload{}, fmt.Errorf("collect updates: %w", err)
	}

	rebootPending, err := client.RebootPending(ctx)
	if err != nil {
		p.logFailure("reboot status", err)

		return results.Payload{}, fmt.Errorf("collect reboot status: %w", err)
	}

	lastUpdate, err := client.LastUpdate(ctx)
	if err != nil {
		p.logFailure("last update", err)

		return results.Payload{}, fmt.Errorf("collect last update: %w", err)
	}

	payload, err := results.Build(repositories, updates)
	if err != nil {
		p.logFailure("results", err)

		return results.Payload{}, fmt.Errorf("build result: %w", err)
	}

	payload.Summary.LastUpdate = results.NewLastUpdate(lastUpdate)
	payload.Summary.RebootPending = rebootPending

	return payload, nil
}

func (p *Plugin) logFailure(stage string, err error) {
	args := []any{
		"stage", stage,
		"error", err.Error(),
	}

	if commandErr, ok := errors.AsType[*dnf.CommandError](err); ok {
		args = append(
			args,
			"dnf_command", commandErr.Command,
			"exit_status", commandErr.ExitStatus,
		)
	}

	p.logger.Error(
		"collection failed",
		args...,
	)
}
