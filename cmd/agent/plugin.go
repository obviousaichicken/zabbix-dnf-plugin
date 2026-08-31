package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/apt"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
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
	errBackendFactory     = errors.New("backend factory is required")
)

type packageCollector interface {
	Collect(context.Context) (packageinfo.Snapshot, error)
}

type advisoryCollector interface {
	SecurityAdvisories(context.Context) (dnf.AdvisoryData, error)
}

type backendRuntime struct {
	Backend    packageinfo.Backend
	Packages   packageCollector
	Advisories advisoryCollector
}

type backendFactory func() (backendRuntime, error)

var (
	_ packageCollector  = (*dnf.Client)(nil)
	_ packageCollector  = (*apt.Client)(nil)
	_ advisoryCollector = (*dnf.Client)(nil)
)

type Plugin struct {
	plugin.Base

	logger           *slog.Logger
	timeout          time.Duration
	factory          backendFactory
	backendOption    string
	configurationErr error

	backendOnce sync.Once
	backend     backendRuntime
	backendErr  error

	lifecycleMu sync.Mutex
	lifecycle   context.Context
	stop        context.CancelFunc
	stopping    bool
	exports     sync.WaitGroup
}

func newPlugin(runner dnf.Runner, logger *slog.Logger) *Plugin {
	return newPluginWithSystem(runner, logger, os.ReadFile, exec.LookPath)
}

func newPluginWithSystem(
	runner dnf.Runner,
	logger *slog.Logger,
	readFile func(string) ([]byte, error),
	lookup func(string) (string, error),
) *Plugin {
	p := &Plugin{
		logger:        logger,
		backendOption: backendAuto,
	}
	p.factory = func() (backendRuntime, error) {
		return p.buildBackend(runner, readFile, lookup)
	}

	return p
}

func (p *Plugin) Configure(global *plugin.GlobalOptions, privateOptions any) {
	backendOption, configurationErr := parseBackendOption(privateOptions)

	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	p.backendOption = backendOption
	p.configurationErr = configurationErr

	if global == nil || global.Timeout <= 0 {
		p.timeout = defaultTimeout

		return
	}

	p.timeout = time.Duration(global.Timeout) * time.Second
}

func (*Plugin) Validate(privateOptions any) error {
	_, err := parseBackendOption(privateOptions)

	return err
}

func (p *Plugin) buildBackend(
	runner dnf.Runner,
	readFile func(string) ([]byte, error),
	lookup func(string) (string, error),
) (backendRuntime, error) {
	p.lifecycleMu.Lock()
	configured := p.backendOption
	configurationErr := p.configurationErr
	p.lifecycleMu.Unlock()
	if configurationErr != nil {
		return backendRuntime{}, configurationErr
	}
	if configured == "" {
		configured = backendAuto
	}

	var osReleaseData []byte
	if configured == backendAuto {
		var err error
		osReleaseData, err = readFile("/etc/os-release")
		if err != nil {
			return backendRuntime{}, fmt.Errorf("read /etc/os-release: %w", err)
		}
	}

	selection, err := selectBackend(configured, osReleaseData, lookup)
	if err != nil {
		return backendRuntime{}, err
	}

	switch selection.Backend {
	case packageinfo.BackendDNF:
		client, err := dnf.NewAtPaths(
			runner,
			selection.Paths["dnf"],
			dnf.RebootCommands{
				RPM:   selection.Paths["rpm"],
				Uname: selection.Paths["uname"],
			},
		)
		if err != nil {
			return backendRuntime{}, fmt.Errorf("initialize DNF: %w", err)
		}

		return backendRuntime{
			Backend:    packageinfo.BackendDNF,
			Packages:   client,
			Advisories: client,
		}, nil
	case packageinfo.BackendAPT:
		client, err := apt.NewAtPaths(runner, apt.CommandPaths{
			APTGet:    selection.Paths["apt-get"],
			APTCache:  selection.Paths["apt-cache"],
			DPKGQuery: selection.Paths["dpkg-query"],
			DPKG:      selection.Paths["dpkg"],
		})
		if err != nil {
			return backendRuntime{}, fmt.Errorf("initialize APT: %w", err)
		}

		return backendRuntime{Backend: packageinfo.BackendAPT, Packages: client}, nil
	case packageinfo.BackendUnknown:
		return backendRuntime{}, errUnsupportedBackend
	default:
		return backendRuntime{}, errUnsupportedBackend
	}
}

func (p *Plugin) Start() {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()

	p.ensureLifecycleLocked()
}

func (p *Plugin) Stop() {
	p.lifecycleMu.Lock()
	if !p.stopping {
		p.stopping = true
		p.ensureLifecycleLocked()
		p.stop()
	}
	p.lifecycleMu.Unlock()

	p.exports.Wait()
}

func (p *Plugin) Export(
	key string,
	params []string,
	provider plugin.ContextProvider,
) (any, error) {
	if key != metricGet && key != metricPackagesGet && key != metricAdvisoriesGet {
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

	var (
		value         any
		repositories  int
		updates       int
		rebootPending bool
		advisories    int
		uniqueCVEs    int
		backend       = packageinfo.BackendDNF
	)
	switch key {
	case metricGet:
		payload, err := p.collect(ctx)
		if err != nil {
			return nil, err
		}
		payload.Collection.DurationMS = time.Since(started).Milliseconds()
		value = payload
		repositories = payload.Summary.Repositories
		updates = payload.Summary.Updates
		rebootPending = payload.Summary.RebootPending
	case metricPackagesGet:
		payload, err := p.collectPackages(ctx)
		if err != nil {
			return nil, err
		}
		payload.Collection.DurationMS = time.Since(started).Milliseconds()
		value = payload
		repositories = payload.Summary.Repositories
		updates = payload.Summary.Updates
		rebootPending = payload.Summary.RebootPending
	case metricAdvisoriesGet:
		payload, err := p.collectAdvisories(ctx)
		if err != nil {
			return nil, err
		}
		payload.Collection.DurationMS = time.Since(started).Milliseconds()
		value = payload
		advisories = payload.Summary.Advisories
		uniqueCVEs = payload.Summary.UniqueCVEs
	}
	if runtime, loadErr := p.loadBackend(); loadErr == nil {
		backend = runtime.Backend
	}

	data, err := json.Marshal(value)
	if err != nil {
		p.logFailure(backend, "encoding", err)

		return nil, fmt.Errorf("marshal result: %w", err)
	}

	if len(data) > maxPayloadBytes {
		err = fmt.Errorf(
			"%w: %d bytes, maximum is %d",
			errPayloadTooLarge,
			len(data),
			maxPayloadBytes,
		)
		p.logFailure(backend, "encoding", err)

		return nil, err
	}

	if p.logger != nil {
		args := []any{
			"backend", backend.String(),
			"key", key,
			"duration_ms", time.Since(started).Milliseconds(),
		}
		if key == metricAdvisoriesGet {
			args = append(args, "advisories", advisories, "unique_cves", uniqueCVEs)
		} else {
			args = append(
				args,
				"repositories", repositories,
				"updates", updates,
				"reboot_pending", rebootPending,
			)
		}
		p.logger.Info("collection completed", args...)
	}

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
	p.ensureLifecycleLocked()

	lifecycle := p.lifecycle
	timeout := requestTimeout(p.timeout, provider)
	p.exports.Add(1)
	p.lifecycleMu.Unlock()

	ctx, cancel := context.WithTimeout(lifecycle, timeout)

	return ctx, func() {
		cancel()
		p.exports.Done()
	}, nil
}

func (p *Plugin) ensureLifecycleLocked() {
	if p.lifecycle == nil {
		p.lifecycle, p.stop = context.WithCancel(context.Background())
	}
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
	runtime, err := p.loadBackend()
	if err != nil {
		p.logFailure(packageinfo.BackendDNF, "initialization", err)

		return results.Payload{}, err
	}
	if runtime.Backend != packageinfo.BackendDNF {
		return results.Payload{}, backendMismatchError(metricGet, runtime.Backend)
	}

	snapshot, err := runtime.Packages.Collect(ctx)
	if err != nil {
		p.logFailure(runtime.Backend, "packages", err)

		return results.Payload{}, err
	}

	payload, err := results.BuildLegacy(snapshot.Repositories, snapshot.Updates)
	if err != nil {
		p.logFailure(runtime.Backend, "results", err)

		return results.Payload{}, fmt.Errorf("build result: %w", err)
	}

	payload.Summary.LastUpdate = results.NewLastUpdate(snapshot.LastUpdate)
	payload.Summary.RebootPending = snapshot.RebootPending

	return payload, nil
}

func backendMismatchError(key string, backend packageinfo.Backend) error {
	return fmt.Errorf("%s requires the DNF backend; detected %s", key, backend.String())
}

func (p *Plugin) collectPackages(ctx context.Context) (results.PackagePayload, error) {
	runtime, err := p.loadBackend()
	if err != nil {
		p.logFailure(packageinfo.BackendDNF, "initialization", err)

		return results.PackagePayload{}, err
	}

	snapshot, err := runtime.Packages.Collect(ctx)
	if err != nil {
		p.logFailure(runtime.Backend, "packages", err)

		return results.PackagePayload{}, err
	}

	payload, err := results.BuildPackages(snapshot)
	if err != nil {
		p.logFailure(runtime.Backend, "results", err)

		return results.PackagePayload{}, fmt.Errorf("build package result: %w", err)
	}

	return payload, nil
}

func (p *Plugin) collectAdvisories(ctx context.Context) (results.AdvisoryPayload, error) {
	runtime, err := p.loadBackend()
	if err != nil {
		p.logFailure(packageinfo.BackendDNF, "initialization", err)

		return results.AdvisoryPayload{}, err
	}
	if runtime.Backend != packageinfo.BackendDNF {
		return results.AdvisoryPayload{}, backendMismatchError(metricAdvisoriesGet, runtime.Backend)
	}

	data, err := runtime.Advisories.SecurityAdvisories(ctx)
	if err != nil {
		p.logFailure(runtime.Backend, "advisories", err)

		return results.AdvisoryPayload{}, err
	}

	payload, err := results.BuildAdvisories(data)
	if err != nil {
		p.logFailure(runtime.Backend, "advisory_results", err)

		return results.AdvisoryPayload{}, fmt.Errorf("build advisory result: %w", err)
	}

	return payload, nil
}

func (p *Plugin) loadBackend() (backendRuntime, error) {
	p.backendOnce.Do(func() {
		if p.factory == nil {
			p.backendErr = errBackendFactory

			return
		}

		p.backend, p.backendErr = p.factory()
		if p.backendErr != nil {
			return
		}
		switch {
		case p.backend.Backend == packageinfo.BackendDNF &&
			(p.backend.Packages == nil || p.backend.Advisories == nil):
			p.backend = backendRuntime{}
			p.backendErr = errors.New("backend factory returned an incomplete DNF runtime")
		case p.backend.Backend == packageinfo.BackendAPT &&
			(p.backend.Packages == nil || p.backend.Advisories != nil):
			p.backend = backendRuntime{}
			p.backendErr = errors.New("backend factory returned an invalid APT runtime")
		case p.backend.Backend == packageinfo.BackendUnknown:
			p.backend = backendRuntime{}
			p.backendErr = errors.New("backend factory returned an incomplete runtime")
		}
	})

	return p.backend, p.backendErr
}

func (p *Plugin) logFailure(backend packageinfo.Backend, stage string, err error) {
	if p.logger == nil {
		return
	}

	args := []any{
		"backend", backend.String(),
		"stage", stage,
		"error", err.Error(),
	}

	var commandFailure command.Failure
	if errors.As(err, &commandFailure) {
		args = append(
			args,
			"operation", commandFailure.Operation(),
			"exit_status", commandFailure.Status(),
			"timed_out", commandFailure.IsTimeout(),
			"canceled", commandFailure.IsCanceled(),
		)
	}

	p.logger.Error(
		"collection failed",
		args...,
	)
}
