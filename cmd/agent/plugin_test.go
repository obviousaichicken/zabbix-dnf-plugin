package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"

	"golang.zabbix.com/sdk/plugin"
)

type packageCollectorFunc func(context.Context) (packageinfo.Snapshot, error)

func (f packageCollectorFunc) Collect(ctx context.Context) (packageinfo.Snapshot, error) {
	return f(ctx)
}

type advisoryCollectorFunc func(context.Context) (dnf.AdvisoryData, error)

func (f advisoryCollectorFunc) SecurityAdvisories(ctx context.Context) (dnf.AdvisoryData, error) {
	return f(ctx)
}

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
	if err := p.Validate(map[string]any{"Backend": "yum"}); !errors.Is(err, errInvalidBackendOption) {
		t.Fatalf("Validate() invalid backend error = %v, want invalid option", err)
	}
}

func TestPluginBuildBackendUsesConfiguredSelection(t *testing.T) {
	t.Parallel()

	readCalls := 0
	lookup := func(name string) (string, error) {
		return "/testbin/" + name, nil
	}
	p := newPluginWithSystem(
		&fakeDNFRunner{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(string) ([]byte, error) {
			readCalls++

			return nil, errors.New("must not read os-release for an override")
		},
		lookup,
	)
	p.Configure(nil, map[string]any{"Backend": "dnf"})
	runtime, err := p.loadBackend()
	if err != nil {
		t.Fatalf("loadBackend() error = %v", err)
	}
	if runtime.Backend != packageinfo.BackendDNF || runtime.Packages == nil || runtime.Advisories == nil {
		t.Fatalf("loadBackend() = %#v, want DNF runtime", runtime)
	}
	if readCalls != 0 {
		t.Fatalf("os-release reads = %d, want 0 for explicit override", readCalls)
	}
}

func TestPluginBuildBackendActivatesAPTSelection(t *testing.T) {
	t.Parallel()

	readCalls := 0
	p := newPluginWithSystem(
		&fakeDNFRunner{},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		func(string) ([]byte, error) {
			readCalls++

			return nil, errors.New("must not read os-release for an override")
		},
		func(name string) (string, error) { return "/testbin/" + name, nil },
	)
	p.Configure(nil, map[string]any{"Backend": "apt"})
	runtime, err := p.loadBackend()
	if err != nil {
		t.Fatalf("loadBackend() error = %v", err)
	}
	if runtime.Backend != packageinfo.BackendAPT || runtime.Packages == nil || runtime.Advisories != nil {
		t.Fatalf("loadBackend() = %#v, want APT runtime", runtime)
	}
	if readCalls != 0 {
		t.Fatalf("os-release reads = %d, want 0 for explicit override", readCalls)
	}
}

func TestPluginRejectsInvalidBackendRuntime(t *testing.T) {
	t.Parallel()

	packages := packageCollectorFunc(func(context.Context) (packageinfo.Snapshot, error) {
		return pluginDNFSnapshot(), nil
	})
	tests := []struct {
		name    string
		runtime backendRuntime
		want    string
	}{
		{
			name:    "DNF missing advisory collector",
			runtime: backendRuntime{Backend: packageinfo.BackendDNF, Packages: packages},
			want:    "incomplete DNF runtime",
		},
		{
			name: "APT has advisory collector",
			runtime: backendRuntime{
				Backend: packageinfo.BackendAPT, Packages: packages, Advisories: successfulAdvisoryCollector(),
			},
			want: "invalid APT runtime",
		},
		{
			name:    "unknown backend",
			runtime: backendRuntime{Backend: packageinfo.BackendUnknown, Packages: packages},
			want:    "incomplete runtime",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			p := &Plugin{factory: func() (backendRuntime, error) { return test.runtime, nil }}
			got, err := p.loadBackend()
			if err == nil || !strings.Contains(err.Error(), test.want) || got != (backendRuntime{}) {
				t.Fatalf("loadBackend() = (%#v, %v), want zero runtime and text %q", got, err, test.want)
			}
		})
	}
}

type fakeDNFRunner struct{}

func (*fakeDNFRunner) Run(context.Context, command.Request) (command.Result, error) {
	return command.Result{}, nil
}

func TestPluginInitializesBackendOnceForConcurrentExports(t *testing.T) {
	t.Parallel()

	var factoryCalls atomic.Int64
	var collectionCalls atomic.Int64
	p := &Plugin{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		factory: func() (backendRuntime, error) {
			factoryCalls.Add(1)

			return backendRuntime{
				Backend:    packageinfo.BackendDNF,
				Advisories: successfulAdvisoryCollector(),
				Packages: packageCollectorFunc(func(context.Context) (packageinfo.Snapshot, error) {
					collectionCalls.Add(1)

					return packageinfo.Snapshot{
						Backend:      packageinfo.BackendDNF,
						Repositories: []packageinfo.Repository{{ID: "updates", Name: "Updates"}},
						Updates: []packageinfo.Update{{
							Name:         "bash",
							RepositoryID: "updates",
							Type:         packageinfo.UpdateTypeOther,
						}},
					}, nil
				}),
			}, nil
		},
	}
	p.Start()

	const workers = 32
	var wait sync.WaitGroup
	errs := make(chan error, workers)
	for range workers {
		wait.Go(func() {
			_, err := p.Export(metricGet, nil, nil)
			errs <- err
		})
	}
	wait.Wait()
	close(errs)
	p.Stop()

	for err := range errs {
		if err != nil {
			t.Fatalf("Export() error = %v", err)
		}
	}
	if got := factoryCalls.Load(); got != 1 {
		t.Fatalf("backend factory calls = %d, want 1", got)
	}
	if got := collectionCalls.Load(); got != workers {
		t.Fatalf("collector calls = %d, want %d", got, workers)
	}
}

func TestPluginStopCancelsConcurrentExports(t *testing.T) {
	t.Parallel()

	const workers = 16
	started := make(chan struct{}, workers)
	p := &Plugin{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		factory: func() (backendRuntime, error) {
			return backendRuntime{
				Backend:    packageinfo.BackendDNF,
				Advisories: successfulAdvisoryCollector(),
				Packages: packageCollectorFunc(func(ctx context.Context) (packageinfo.Snapshot, error) {
					started <- struct{}{}
					<-ctx.Done()

					return packageinfo.Snapshot{}, ctx.Err()
				}),
			}, nil
		},
	}
	p.Start()

	errs := make(chan error, workers)
	for range workers {
		go func() {
			_, err := p.Export(metricGet, nil, nil)
			errs <- err
		}()
	}
	for range workers {
		<-started
	}

	p.Stop()
	for range workers {
		if err := <-errs; !errors.Is(err, context.Canceled) {
			t.Fatalf("Export() error = %v, want context canceled", err)
		}
	}
	if _, err := p.Export(metricGet, nil, nil); !errors.Is(err, errPluginStopping) {
		t.Fatalf("Export() after Stop() error = %v, want plugin stopping", err)
	}
}

func TestPluginExportRejectsInvalidRequest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		key     string
		params  []string
		wantErr error
		want    string
	}{
		{
			name:    "unsupported key",
			key:     "unsupported",
			wantErr: errUnsupportedItemKey,
			want:    `unsupported item key "unsupported"`,
		},
		{
			name:    "item key parameters",
			key:     metricGet,
			params:  []string{"unexpected"},
			wantErr: errItemKeyParameters,
			want:    "item key does not accept parameters: dnf.get",
		},
		{
			name:    "packages item key parameters",
			key:     metricPackagesGet,
			params:  []string{"unexpected"},
			wantErr: errItemKeyParameters,
			want:    "item key does not accept parameters: packages.get",
		},
		{
			name:    "advisories item key parameters",
			key:     metricAdvisoriesGet,
			params:  []string{"unexpected"},
			wantErr: errItemKeyParameters,
			want:    "item key does not accept parameters: dnf.advisories.get",
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
			if err.Error() != testCase.want {
				t.Fatalf("Export() error = %q, want %q", err, testCase.want)
			}
		})
	}
}

func TestPluginAPTExportsGenericSchemaAndRejectsDNFKeys(t *testing.T) {
	t.Parallel()

	var collectionCalls atomic.Int64
	p := &Plugin{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		factory: func() (backendRuntime, error) {
			return backendRuntime{
				Backend: packageinfo.BackendAPT,
				Packages: packageCollectorFunc(func(context.Context) (packageinfo.Snapshot, error) {
					collectionCalls.Add(1)

					return pluginAPTSnapshot(), nil
				}),
			}, nil
		},
	}
	p.Start()
	defer p.Stop()

	value, err := p.Export(metricPackagesGet, nil, nil)
	if err != nil {
		t.Fatalf("Export(packages.get) error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(value.(string)), &payload); err != nil {
		t.Fatalf("decode packages.get: %v", err)
	}
	if payload["schema_version"] != float64(1) || payload["backend"] != "apt" {
		t.Fatalf("packages.get schema = %#v", payload)
	}
	capabilities := payload["capabilities"].(map[string]any)
	if capabilities["last_update"] != "best_effort" || capabilities["metadata_age"] != "supported" {
		t.Fatalf("APT capabilities = %#v", capabilities)
	}

	for _, test := range []struct {
		key  string
		want string
	}{
		{key: metricGet, want: "dnf.get requires the DNF backend; detected apt"},
		{key: metricAdvisoriesGet, want: "dnf.advisories.get requires the DNF backend; detected apt"},
	} {
		_, err := p.Export(test.key, nil, nil)
		if err == nil || err.Error() != test.want {
			t.Errorf("Export(%s) error = %q, want %q", test.key, err, test.want)
		}
	}
	if got := collectionCalls.Load(); got != 1 {
		t.Errorf("APT collector calls = %d, want only packages.get collection", got)
	}
}

func TestPluginDNFExportsAdvisorySchema(t *testing.T) {
	t.Parallel()

	p := &Plugin{
		factory: func() (backendRuntime, error) {
			return backendRuntime{
				Backend:    packageinfo.BackendDNF,
				Advisories: successfulAdvisoryCollector(),
				Packages: packageCollectorFunc(func(context.Context) (packageinfo.Snapshot, error) {
					return pluginDNFSnapshot(), nil
				}),
			}, nil
		},
	}
	p.Start()
	defer p.Stop()

	value, err := p.Export(metricAdvisoriesGet, nil, nil)
	if err != nil {
		t.Fatalf("Export(dnf.advisories.get) error = %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(value.(string)), &payload); err != nil {
		t.Fatalf("decode dnf.advisories.get: %v", err)
	}
	if payload["schema_version"] != float64(1) || !payload["collection"].(map[string]any)["complete"].(bool) {
		t.Fatalf("dnf.advisories.get schema = %#v", payload)
	}
	summary := payload["summary"].(map[string]any)
	if summary["advisories"] != float64(1) || summary["unique_cves"] != float64(1) {
		t.Fatalf("dnf.advisories.get summary = %#v", summary)
	}
}

func TestPluginExportDispatchesLegacyAndGenericSchemas(t *testing.T) {
	t.Parallel()

	snapshot := pluginDNFSnapshot()
	p := &Plugin{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		factory: func() (backendRuntime, error) {
			return backendRuntime{
				Backend:    packageinfo.BackendDNF,
				Advisories: successfulAdvisoryCollector(),
				Packages: packageCollectorFunc(func(context.Context) (packageinfo.Snapshot, error) {
					return snapshot, nil
				}),
			}, nil
		},
	}
	p.Start()
	defer p.Stop()

	legacyValue, err := p.Export(metricGet, nil, nil)
	if err != nil {
		t.Fatalf("Export(dnf.get) error = %v", err)
	}
	genericValue, err := p.Export(metricPackagesGet, nil, nil)
	if err != nil {
		t.Fatalf("Export(packages.get) error = %v", err)
	}

	var legacy map[string]any
	if err := json.Unmarshal([]byte(legacyValue.(string)), &legacy); err != nil {
		t.Fatalf("decode dnf.get: %v", err)
	}
	if _, exists := legacy["schema_version"]; exists {
		t.Fatalf("dnf.get unexpectedly contains schema_version: %#v", legacy)
	}

	var generic map[string]any
	if err := json.Unmarshal([]byte(genericValue.(string)), &generic); err != nil {
		t.Fatalf("decode packages.get: %v", err)
	}
	if generic["schema_version"] != float64(1) || generic["backend"] != "dnf" {
		t.Fatalf("packages.get schema = %#v", generic)
	}
	if legacySummary := legacy["summary"].(map[string]any); legacySummary["updates"] != generic["summary"].(map[string]any)["updates"] {
		t.Fatalf("legacy and generic update facts differ: legacy=%#v generic=%#v", legacy, generic)
	}

	advisoryValue, err := p.Export(metricAdvisoriesGet, nil, nil)
	if err != nil {
		t.Fatalf("Export(dnf.advisories.get) error = %v", err)
	}
	var advisory map[string]any
	if err := json.Unmarshal([]byte(advisoryValue.(string)), &advisory); err != nil {
		t.Fatalf("decode dnf.advisories.get: %v", err)
	}
	if advisory["schema_version"] != float64(1) || advisory["summary"].(map[string]any)["advisories"] != float64(1) {
		t.Fatalf("dnf.advisories.get schema = %#v", advisory)
	}
}

func TestPluginAdvisoryFailureIsIsolated(t *testing.T) {
	t.Parallel()

	advisoryErr := errors.New("advisory collection failed")
	var packageCalls atomic.Int64
	var advisoryCalls atomic.Int64
	p := &Plugin{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		factory: func() (backendRuntime, error) {
			return backendRuntime{
				Backend: packageinfo.BackendDNF,
				Packages: packageCollectorFunc(func(context.Context) (packageinfo.Snapshot, error) {
					packageCalls.Add(1)

					return pluginDNFSnapshot(), nil
				}),
				Advisories: advisoryCollectorFunc(func(context.Context) (dnf.AdvisoryData, error) {
					advisoryCalls.Add(1)

					return dnf.AdvisoryData{}, advisoryErr
				}),
			}, nil
		},
	}
	p.Start()
	defer p.Stop()

	if _, err := p.Export(metricAdvisoriesGet, nil, nil); !errors.Is(err, advisoryErr) {
		t.Fatalf("Export(dnf.advisories.get) error = %v, want %v", err, advisoryErr)
	}
	for _, key := range []string{metricGet, metricPackagesGet} {
		if _, err := p.Export(key, nil, nil); err != nil {
			t.Fatalf("Export(%s) after advisory failure error = %v", key, err)
		}
	}
	if packageCalls.Load() != 2 || advisoryCalls.Load() != 1 {
		t.Fatalf("collector calls packages=%d advisories=%d, want 2/1", packageCalls.Load(), advisoryCalls.Load())
	}
}

func pluginDNFSnapshot() packageinfo.Snapshot {
	update := packageinfo.Update{
		Name:         "bash",
		Epoch:        "0",
		Version:      "5.2",
		Release:      "1.el9",
		Arch:         "x86_64",
		RepositoryID: "updates",
		Type:         packageinfo.UpdateTypeSecurity,
	}
	packageinfo.SetIdentity(packageinfo.BackendDNF, &update)

	return packageinfo.Snapshot{
		Backend: packageinfo.BackendDNF,
		Capabilities: packageinfo.Capabilities{
			Classification: packageinfo.ClassificationCapabilities{
				Security:    packageinfo.CapabilitySupported,
				Bugfix:      packageinfo.CapabilitySupported,
				Enhancement: packageinfo.CapabilitySupported,
				Other:       packageinfo.CapabilitySupported,
			},
			RepositoryAttribution: packageinfo.CapabilitySupported,
			RebootDetection:       packageinfo.CapabilitySupported,
			LastUpdate:            packageinfo.CapabilitySupported,
			MetadataAge:           packageinfo.CapabilityUnsupported,
		},
		Repositories: []packageinfo.Repository{{ID: "updates", Name: "Updates"}},
		Updates:      []packageinfo.Update{update},
	}
}

func successfulAdvisoryCollector() advisoryCollector {
	return advisoryCollectorFunc(func(context.Context) (dnf.AdvisoryData, error) {
		return pluginAdvisoryData(), nil
	})
}

func pluginAdvisoryData() dnf.AdvisoryData {
	collectedAt := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	issuedAt := time.Date(2026, time.August, 20, 10, 0, 0, 0, time.UTC)

	return dnf.AdvisoryData{
		CollectedAt: collectedAt,
		Capabilities: dnf.AdvisoryCapabilities{
			DetailsComplete: true, CVEsComplete: true, IssueDatesComplete: true,
		},
		Advisories: []dnf.Advisory{{
			ID:       "TEST-2026:1",
			Type:     "security",
			Severity: dnf.AdvisorySeverityImportant,
			Title:    "Test security update",
			IssuedAt: &issuedAt,
			CVEIDs:   []string{"CVE-2026-1234"},
			AffectedUpdates: []dnf.NEVRA{{
				Name: "bash", Epoch: "0", Version: "5.2", Release: "1.el9", Arch: "x86_64",
			}},
		}},
	}
}

func pluginAPTSnapshot() packageinfo.Snapshot {
	refreshedAt := time.Date(2026, time.August, 31, 10, 0, 0, 0, time.UTC)
	age := int64(1800)
	update := packageinfo.Update{
		Name:         "openssl",
		Epoch:        "3",
		Version:      "3.0.2",
		Release:      "0ubuntu1.20",
		Arch:         "amd64",
		RepositoryID: "apt-security",
		Type:         packageinfo.UpdateTypeSecurity,
	}
	packageinfo.SetIdentity(packageinfo.BackendAPT, &update)

	return packageinfo.Snapshot{
		Backend: packageinfo.BackendAPT,
		Capabilities: packageinfo.Capabilities{
			Classification: packageinfo.ClassificationCapabilities{
				Security:    packageinfo.CapabilitySupported,
				Bugfix:      packageinfo.CapabilityUnsupported,
				Enhancement: packageinfo.CapabilityUnsupported,
				Other:       packageinfo.CapabilitySupported,
			},
			RepositoryAttribution: packageinfo.CapabilitySupported,
			RebootDetection:       packageinfo.CapabilitySupported,
			LastUpdate:            packageinfo.CapabilityBestEffort,
			MetadataAge:           packageinfo.CapabilitySupported,
		},
		Metadata: packageinfo.Metadata{RefreshedAt: &refreshedAt, AgeSeconds: &age},
		Repositories: []packageinfo.Repository{
			{ID: "apt-security", Name: "Ubuntu (noble-security) [main]"},
		},
		Updates: []packageinfo.Update{update},
	}
}

func TestLogFailureDoesNotLogDNFStderr(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	p := new(Plugin)
	p.logger = slog.New(slog.NewJSONHandler(&output, nil))

	p.logFailure(packageinfo.BackendDNF, "updates", &dnf.CommandError{
		Command:    "/usr/bin/dnf repoquery",
		ExitStatus: 1,
		Stderr:     "raw stderr marker",
		Err:        context.Canceled,
	})

	if strings.Contains(output.String(), "raw stderr marker") {
		t.Fatalf("log contains raw command stderr: %s", output.String())
	}
	for _, field := range []string{
		`"backend":"dnf"`,
		`"stage":"updates"`,
		`"operation":"/usr/bin/dnf repoquery"`,
		`"exit_status":1`,
		`"canceled":true`,
	} {
		if !strings.Contains(output.String(), field) {
			t.Fatalf("structured log does not contain %s: %s", field, output.String())
		}
	}
}
