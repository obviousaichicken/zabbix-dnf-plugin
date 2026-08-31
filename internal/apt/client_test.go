//nolint:testpackage // white-box construction verifies commands, filesystem, and clock injection.
package apt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

func TestClientPackagesCollectsSecurityUpdate(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: readAPTFixture(t, "debian13", "indextargets.txt")},
		{stdout: readAPTFixture(t, "debian13", "dpkg-query.txt")},
		{stdout: readAPTFixture(t, "debian13", "policy.txt")},
		{exitCode: 0},
	}}
	stat := func(string) (fs.FileInfo, error) {
		return fakeFileInfo{mode: 0o644, modified: now.Add(-2 * time.Hour)}, nil
	}
	client := mustAPTClient(t, runner, stat, func() time.Time { return now })

	data, err := client.Packages(context.Background())
	if err != nil {
		t.Fatalf("Packages() error = %v", err)
	}
	if len(data.Repositories) != 2 || len(data.Updates) != 1 {
		t.Fatalf("Packages() repositories/updates = %d/%d, want 2/1", len(data.Repositories), len(data.Updates))
	}
	update := data.Updates[0]
	if update.Name != "libssl3t64" || update.Arch != "amd64" ||
		update.FullVersion != "3.5.7-1~deb13u2" ||
		update.Identifier != "libssl3t64:amd64=3.5.7-1~deb13u2" ||
		update.Type != packageinfo.UpdateTypeSecurity {
		t.Errorf("update = %#v", update)
	}
	if data.Metadata.RefreshedAt == nil || !data.Metadata.RefreshedAt.Equal(now.Add(-2*time.Hour)) ||
		data.Metadata.AgeSeconds == nil || *data.Metadata.AgeSeconds != 7200 {
		t.Errorf("metadata = %#v", data.Metadata)
	}

	wantRequests := []struct {
		name string
		args []string
	}{
		{name: "/usr/bin/apt-get", args: []string{"indextargets"}},
		{name: "/usr/bin/dpkg-query", args: []string{"--show", "--showformat=" + installedQueryFormat}},
		{name: "/usr/bin/apt-cache", args: []string{"policy", "libssl3t64:amd64"}},
		{name: "/usr/bin/dpkg", args: []string{"--compare-versions", "3.5.7-1~deb13u2", "gt", "3.5.6-1~deb13u2"}},
	}
	requests := runner.Requests()
	if len(requests) != len(wantRequests) {
		t.Fatalf("requests = %d, want %d", len(requests), len(wantRequests))
	}
	for index, request := range requests {
		if request.Name != wantRequests[index].name || !slices.Equal(request.Args, wantRequests[index].args) {
			t.Errorf("request[%d] = %q %q, want %q %q", index, request.Name, request.Args, wantRequests[index].name, wantRequests[index].args)
		}
		if request.Env["LC_ALL"] != "C" || request.Env["LANG"] != "C" {
			t.Errorf("request[%d] locale = %#v, want C", index, request.Env)
		}
	}
	if !slices.Equal(requests[3].AcceptedExitCodes, []int{1}) {
		t.Errorf("dpkg accepted exit codes = %v, want [1]", requests[3].AcceptedExitCodes)
	}
}

func TestClientPackagesAllowsNoPendingUpdates(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: readAPTFixture(t, "debian12", "indextargets.txt")},
		{stdout: readAPTFixture(t, "debian12", "dpkg-query.txt")},
		{stdout: readAPTFixture(t, "debian12", "policy.txt")},
	}}
	client := mustAPTClient(
		t,
		runner,
		func(string) (fs.FileInfo, error) {
			return fakeFileInfo{mode: 0o644, modified: now.Add(-time.Hour)}, nil
		},
		func() time.Time { return now },
	)

	data, err := client.Packages(context.Background())
	if err != nil {
		t.Fatalf("Packages() error = %v", err)
	}
	if data.Updates == nil || len(data.Updates) != 0 {
		t.Fatalf("Updates = %#v, want non-nil empty slice", data.Updates)
	}
	if got := len(runner.Requests()); got != 3 {
		t.Fatalf("commands = %d, want 3 without version comparison", got)
	}
}

func TestClientPackagesClassifiesEveryWinningPrioritySource(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: readAPTFixture(t, "ubuntu2204", "indextargets.txt")},
		{stdout: readAPTFixture(t, "ubuntu2204", "dpkg-query.txt")},
		{stdout: readAPTFixture(t, "ubuntu2204", "policy.txt")},
		{exitCode: 0},
	}}
	client := mustAPTClient(
		t,
		runner,
		func(string) (fs.FileInfo, error) { return fakeFileInfo{mode: 0o644, modified: now}, nil },
		func() time.Time { return now },
	)

	data, err := client.Packages(context.Background())
	if err != nil {
		t.Fatalf("Packages() error = %v", err)
	}
	if len(data.Updates) != 1 || data.Updates[0].Type != packageinfo.UpdateTypeSecurity {
		t.Fatalf("Updates = %#v, want security classification from tied winning source", data.Updates)
	}
	selectedRepository := ""
	for _, repository := range data.Repositories {
		if repository.ID == data.Updates[0].RepositoryID {
			selectedRepository = repository.Name
		}
	}
	if !strings.Contains(selectedRepository, "jammy-updates") {
		t.Errorf("tie selected repository %q, want first APT source jammy-updates", selectedRepository)
	}
}

func TestClientPackagesUsesHighestSourcePriority(t *testing.T) {
	t.Parallel()

	normal := aptTargetRecord(targetRecordOptions{descriptionURL: "https://normal.example/debian"})
	security := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://security.example/debian",
		filename:       "/var/lib/apt/lists/security_Packages",
		label:          "Debian-Security",
		suite:          "stable-security",
		codename:       "trixie-security",
	})
	installed := "priority-pkg:amd64|amd64|1.0-1|installed\n"
	policy := `priority-pkg:
  Installed: 1.0-1
  Candidate: 2.0-1
  Version table:
     2.0-1 700
        500 https://normal.example/debian trixie/main amd64 Packages
        700 https://security.example/debian trixie-security/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: []byte(normal + security)},
		{stdout: []byte(installed)},
		{stdout: []byte(policy)},
		{exitCode: 0},
	}}
	client := mustAPTClient(
		t,
		runner,
		func(string) (fs.FileInfo, error) { return fakeFileInfo{mode: 0o644, modified: now}, nil },
		func() time.Time { return now },
	)

	data, err := client.Packages(context.Background())
	if err != nil {
		t.Fatalf("Packages() error = %v", err)
	}
	if len(data.Updates) != 1 || data.Updates[0].Type != packageinfo.UpdateTypeSecurity {
		t.Fatalf("Updates = %#v, want highest-priority security source", data.Updates)
	}
}

func TestClientPackagesDetectsPackageStateRace(t *testing.T) {
	t.Parallel()

	policy := strings.ReplaceAll(
		string(readAPTFixture(t, "debian13", "policy.txt")),
		"3.5.6-1~deb13u2",
		"3.5.6-1~deb13u1",
	)
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: readAPTFixture(t, "debian13", "indextargets.txt")},
		{stdout: readAPTFixture(t, "debian13", "dpkg-query.txt")},
		{stdout: []byte(policy)},
	}}
	client := mustAPTClient(
		t,
		runner,
		func(string) (fs.FileInfo, error) { return fakeFileInfo{mode: 0o644, modified: now}, nil },
		func() time.Time { return now },
	)

	_, err := client.Packages(context.Background())
	if err == nil || !strings.Contains(err.Error(), "package state changed") {
		t.Fatalf("Packages() error = %v, want package-state race", err)
	}
	if got := len(runner.Requests()); got != 3 {
		t.Fatalf("commands = %d, want no dpkg comparison after race", got)
	}
}

func TestClientPackagesExcludesCandidateDowngrade(t *testing.T) {
	t.Parallel()

	index := aptTargetRecord(targetRecordOptions{})
	installed := "downgrade-pkg:amd64|amd64|2.0-1|installed\n"
	policy := `downgrade-pkg:
  Installed: 2.0-1
  Candidate: 1.0-1
  Version table:
 *** 2.0-1 100
        100 /var/lib/dpkg/status
     1.0-1 500
        500 https://packages.example/debian trixie/main amd64 Packages
`
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: []byte(index)},
		{stdout: []byte(installed)},
		{stdout: []byte(policy)},
		{exitCode: 1},
	}}
	client := mustAPTClient(
		t,
		runner,
		func(string) (fs.FileInfo, error) { return fakeFileInfo{mode: 0o644, modified: now}, nil },
		func() time.Time { return now },
	)

	data, err := client.Packages(context.Background())
	if err != nil {
		t.Fatalf("Packages() error = %v", err)
	}
	if len(data.Updates) != 0 {
		t.Fatalf("Updates = %#v, want downgrade excluded", data.Updates)
	}
}

func TestClientPackagesBatchesPolicyCommands(t *testing.T) {
	t.Parallel()

	var installed strings.Builder
	var firstPolicy strings.Builder
	var secondPolicy strings.Builder
	for index := range 513 {
		name := fmt.Sprintf("pkg-%03d", index)
		fmt.Fprintf(&installed, "%s:amd64|amd64|1.0-1|installed\n", name)
		destination := &firstPolicy
		if index >= 512 {
			destination = &secondPolicy
		}
		fmt.Fprintf(destination, `%s:
  Installed: 1.0-1
  Candidate: 1.0-1
  Version table:
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`, name)
	}
	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: []byte(aptTargetRecord(targetRecordOptions{}))},
		{stdout: []byte(installed.String())},
		{stdout: []byte(firstPolicy.String())},
		{stdout: []byte(secondPolicy.String())},
	}}
	client := mustAPTClient(
		t,
		runner,
		func(string) (fs.FileInfo, error) { return fakeFileInfo{mode: 0o644, modified: now}, nil },
		func() time.Time { return now },
	)

	data, err := client.Packages(context.Background())
	if err != nil {
		t.Fatalf("Packages() error = %v", err)
	}
	if len(data.Updates) != 0 {
		t.Fatalf("Updates = %d, want 0", len(data.Updates))
	}
	requests := runner.Requests()
	if len(requests) != 4 || len(requests[2].Args) != 513 || len(requests[3].Args) != 2 {
		t.Fatalf("policy request sizes = %#v", requestArgumentLengths(requests))
	}
}

func TestClientPackagesHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	client := mustAPTClient(
		t,
		cancelingAPTRunner{},
		func(string) (fs.FileInfo, error) { return nil, errors.New("unused") },
		time.Now,
	)

	_, err := client.Packages(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Packages() error = %v, want context canceled", err)
	}
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Operation() != "apt-get indextargets" || !commandErr.IsCanceled() {
		t.Fatalf("Packages() command error = %#v", commandErr)
	}
}

func TestClientPackagesRejectsOversizeCommandOutput(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	index := []byte(aptTargetRecord(targetRecordOptions{}))
	installed := []byte("pkg:amd64|amd64|1.0-1|installed\n")
	tests := []struct {
		name      string
		responses []fakeAPTResponse
		want      string
	}{
		{
			name:      "repository indexes",
			responses: []fakeAPTResponse{{stdout: make([]byte, maxRepositoryIndexBytes+1)}},
			want:      "repository index output exceeds",
		},
		{
			name: "installed packages",
			responses: []fakeAPTResponse{
				{stdout: index},
				{stdout: make([]byte, maxInstalledOutputBytes+1)},
			},
			want: "installed-package output exceeds",
		},
		{
			name: "package policy",
			responses: []fakeAPTResponse{
				{stdout: index},
				{stdout: installed},
				{stdout: make([]byte, maxPolicyOutputBytes+1)},
			},
			want: "policy output exceeds",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := mustAPTClient(
				t,
				&fakeAPTRunner{responses: test.responses},
				func(string) (fs.FileInfo, error) { return fakeFileInfo{mode: 0o644, modified: now}, nil },
				func() time.Time { return now },
			)
			_, err := client.Packages(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Packages() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestClientIndexMetadataUsesOldestUniqueIndex(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	modified := map[string]time.Time{
		"/one": now.Add(-time.Hour),
		"/two": now.Add(-3 * time.Hour),
	}
	calls := make(map[string]int)
	client := mustAPTClient(
		t,
		&fakeAPTRunner{},
		func(path string) (fs.FileInfo, error) {
			calls[path]++
			return fakeFileInfo{mode: 0o644, modified: modified[path]}, nil
		},
		func() time.Time { return now },
	)
	targets := []IndexTarget{{Filename: "/one"}, {Filename: "/two"}, {Filename: "/one"}}

	metadata, err := client.indexMetadata(context.Background(), targets)
	if err != nil {
		t.Fatalf("indexMetadata() error = %v", err)
	}
	if metadata.RefreshedAt == nil || !metadata.RefreshedAt.Equal(modified["/two"]) ||
		metadata.AgeSeconds == nil || *metadata.AgeSeconds != 10800 {
		t.Errorf("metadata = %#v", metadata)
	}
	if !reflect.DeepEqual(calls, map[string]int{"/one": 1, "/two": 1}) {
		t.Errorf("stat calls = %#v", calls)
	}
}

func TestClientIndexMetadataErrorsArePathSafe(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("permission denied")
	client := mustAPTClient(
		t,
		&fakeAPTRunner{},
		func(string) (fs.FileInfo, error) { return nil, sentinel },
		time.Now,
	)

	_, err := client.indexMetadata(context.Background(), []IndexTarget{{Filename: "/secret/alice:s3cr3t/index"}})
	if !errors.Is(err, sentinel) {
		t.Fatalf("indexMetadata() error = %v, want sentinel", err)
	}
	for _, secret := range []string{"alice", "s3cr3t", "/secret/"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("index metadata error contains path detail %q: %v", secret, err)
		}
	}
}

func TestClientIndexMetadataRejectsMissingOrNonRegularIndexes(t *testing.T) {
	t.Parallel()

	client := mustAPTClient(
		t,
		&fakeAPTRunner{},
		func(string) (fs.FileInfo, error) {
			return fakeFileInfo{mode: fs.ModeDir, modified: time.Now()}, nil
		},
		time.Now,
	)
	if _, err := client.indexMetadata(context.Background(), nil); err == nil || !strings.Contains(err.Error(), "no enabled") {
		t.Errorf("empty indexes error = %v", err)
	}
	if _, err := client.indexMetadata(context.Background(), []IndexTarget{{Filename: "/directory"}}); err == nil ||
		!strings.Contains(err.Error(), "not a regular file") {
		t.Errorf("directory index error = %v", err)
	}
}

func TestClientConstructorValidation(t *testing.T) {
	t.Parallel()

	paths := testAPTPaths()
	if _, err := NewAtPaths(nil, paths); !errors.Is(err, errRunnerRequired) {
		t.Errorf("NewAtPaths(nil) error = %v", err)
	}
	for _, field := range []string{"apt-get", "apt-cache", "dpkg-query", "dpkg"} {
		invalid := paths
		switch field {
		case "apt-get":
			invalid.APTGet = ""
		case "apt-cache":
			invalid.APTCache = ""
		case "dpkg-query":
			invalid.DPKGQuery = ""
		case "dpkg":
			invalid.DPKG = ""
		}
		if _, err := NewAtPaths(&fakeAPTRunner{}, invalid); err == nil || !strings.Contains(err.Error(), field+" path") {
			t.Errorf("missing %s error = %v", field, err)
		}
	}
	if _, err := newClientForTest(&fakeAPTRunner{}, paths, nil, time.Now); err == nil {
		t.Error("nil stat function was accepted")
	}
	if _, err := newClientForTest(&fakeAPTRunner{}, paths, os.Stat, nil); err == nil {
		t.Error("nil clock was accepted")
	}
}

func TestNewResolvesAPTCommands(t *testing.T) {
	binDirectory := t.TempDir()
	for _, name := range []string{"apt-get", "apt-cache", "dpkg-query", "dpkg"} {
		path := filepath.Join(binDirectory, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDirectory)

	client, err := New(&fakeAPTRunner{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	want := CommandPaths{
		APTGet:    filepath.Join(binDirectory, "apt-get"),
		APTCache:  filepath.Join(binDirectory, "apt-cache"),
		DPKGQuery: filepath.Join(binDirectory, "dpkg-query"),
		DPKG:      filepath.Join(binDirectory, "dpkg"),
	}
	if client.paths != want {
		t.Errorf("paths = %#v, want %#v", client.paths, want)
	}
}

func TestPreferredCandidateSource(t *testing.T) {
	t.Parallel()

	sources := []PolicySource{
		{RepositoryID: "first", Priority: 500},
		{RepositoryID: "higher", Priority: 700},
		{RepositoryID: "tie", Priority: 700},
	}
	got, err := preferredCandidateSource(sources)
	if err != nil {
		t.Fatalf("preferredCandidateSource() error = %v", err)
	}
	if got.RepositoryID != "higher" {
		t.Errorf("preferred source = %#v, want first source at highest priority", got)
	}
	if _, err := preferredCandidateSource(nil); err == nil {
		t.Error("empty candidate sources were accepted")
	}

	if !winningCandidateIsSecurity([]PolicySource{
		{Priority: 700},
		{Priority: 700, Security: true},
		{Priority: 500, Security: false},
	}) {
		t.Error("security source tied at the winning priority was ignored")
	}
	if winningCandidateIsSecurity([]PolicySource{
		{Priority: 700},
		{Priority: 500, Security: true},
	}) {
		t.Error("lower-priority security source classified the winning candidate")
	}
}

type fakeAPTResponse struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	err      error
}

type fakeAPTRunner struct {
	mu        sync.Mutex
	responses []fakeAPTResponse
	requests  []command.Request
}

func (runner *fakeAPTRunner) Run(
	_ context.Context,
	request command.Request,
) (command.Result, error) {
	runner.mu.Lock()
	defer runner.mu.Unlock()

	runner.requests = append(runner.requests, cloneCommandRequest(request))
	if len(runner.requests) > len(runner.responses) {
		return command.Result{ExitCode: -1}, errors.New("unexpected APT test command")
	}
	response := runner.responses[len(runner.requests)-1]

	return command.Result{
		Stdout:   response.stdout,
		Stderr:   response.stderr,
		ExitCode: response.exitCode,
	}, response.err
}

func (runner *fakeAPTRunner) Requests() []command.Request {
	runner.mu.Lock()
	defer runner.mu.Unlock()

	requests := make([]command.Request, len(runner.requests))
	for index, request := range runner.requests {
		requests[index] = cloneCommandRequest(request)
	}

	return requests
}

type cancelingAPTRunner struct{}

func (cancelingAPTRunner) Run(ctx context.Context, _ command.Request) (command.Result, error) {
	<-ctx.Done()

	return command.Result{ExitCode: -1}, ctx.Err()
}

type fakeFileInfo struct {
	mode     fs.FileMode
	modified time.Time
}

func (fakeFileInfo) Name() string            { return "index" }
func (fakeFileInfo) Size() int64             { return 1 }
func (info fakeFileInfo) Mode() fs.FileMode  { return info.mode }
func (info fakeFileInfo) ModTime() time.Time { return info.modified }
func (fakeFileInfo) IsDir() bool             { return false }
func (fakeFileInfo) Sys() any                { return nil }

func mustAPTClient(
	t *testing.T,
	runner Runner,
	stat func(string) (fs.FileInfo, error),
	now func() time.Time,
) *Client {
	t.Helper()

	client, err := newClientForTest(runner, testAPTPaths(), stat, now)
	if err != nil {
		t.Fatalf("construct APT client: %v", err)
	}

	return client
}

func testAPTPaths() CommandPaths {
	return CommandPaths{
		APTGet:    "/usr/bin/apt-get",
		APTCache:  "/usr/bin/apt-cache",
		DPKGQuery: "/usr/bin/dpkg-query",
		DPKG:      "/usr/bin/dpkg",
	}
}

func cloneCommandRequest(request command.Request) command.Request {
	request.Args = append([]string(nil), request.Args...)
	request.AcceptedExitCodes = append([]int(nil), request.AcceptedExitCodes...)
	request.Env = map[string]string{
		"LC_ALL": request.Env["LC_ALL"],
		"LANG":   request.Env["LANG"],
	}

	return request
}

func requestArgumentLengths(requests []command.Request) []int {
	lengths := make([]int, len(requests))
	for index, request := range requests {
		lengths[index] = len(request.Args)
	}

	return lengths
}
