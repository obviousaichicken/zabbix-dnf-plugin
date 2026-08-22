//nolint:testpackage // constructing Client directly isolates command argument behavior.
package dnf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestNewRequiresRunner(t *testing.T) {
	t.Parallel()

	_, err := New(nil)
	if !errors.Is(err, errRunnerRequired) {
		t.Fatalf("New() error = %v, want %v", err, errRunnerRequired)
	}
}

func TestNewResolvesCommandsFromPATH(t *testing.T) {
	binDir := t.TempDir()
	for _, name := range []string{"dnf", "rpm", "uname"} {
		path := filepath.Join(binDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	t.Setenv("PATH", binDir)

	client, err := New(&fakeRunner{})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client.path != filepath.Join(binDir, "dnf") {
		t.Fatalf("New().path = %q, want temporary dnf path", client.path)
	}
	if client.rebootChecker.commands.RPM != filepath.Join(binDir, "rpm") ||
		client.rebootChecker.commands.Uname != filepath.Join(binDir, "uname") {
		t.Fatalf("New() reboot commands = %#v, want temporary command paths", client.rebootChecker.commands)
	}
}

func TestNewReturnsLookupErrors(t *testing.T) {
	t.Run("dnf missing", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())

		_, err := New(&fakeRunner{})
		if err == nil || !strings.Contains(err.Error(), "find dnf") {
			t.Fatalf("New() error = %v, want dnf lookup failure", err)
		}
	})

	t.Run("reboot command missing", func(t *testing.T) {
		binDir := t.TempDir()
		dnfPath := filepath.Join(binDir, "dnf")
		if err := os.WriteFile(dnfPath, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatalf("write dnf: %v", err)
		}
		t.Setenv("PATH", binDir)

		_, err := New(&fakeRunner{})
		if err == nil || !strings.Contains(err.Error(), "find reboot commands") {
			t.Fatalf("New() error = %v, want reboot command lookup failure", err)
		}
	})
}

func TestRepositories(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: []fakeResponse{{stdout: []byte(
			"repo id repo name\n" +
				"baseos Red Hat Enterprise Linux 9 - BaseOS\n",
		)}},
	}
	client := &Client{runner: runner, path: "/usr/bin/dnf"}

	got, err := client.Repositories(context.Background())
	if err != nil {
		t.Fatalf("Repositories() error = %v", err)
	}
	want := []Repository{{ID: "baseos", Name: "Red Hat Enterprise Linux 9 - BaseOS"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Repositories() = %#v, want %#v", got, want)
	}

	wantArgs := []string{"--assumeno", "-q", "repolist"}
	if !slices.Equal(runner.requests[0].Args, wantArgs) {
		t.Fatalf("Repositories() arguments = %q, want %q", runner.requests[0].Args, wantArgs)
	}
}

func TestRepositoriesReturnsCommandAndParseErrors(t *testing.T) {
	t.Parallel()

	commandErr := errors.New("dnf unavailable")
	tests := []struct {
		name      string
		response  fakeResponse
		wantCause error
		wantText  string
	}{
		{
			name:      "command failure",
			response:  fakeResponse{err: commandErr},
			wantCause: commandErr,
			wantText:  "list repositories",
		},
		{
			name:     "invalid output",
			response: fakeResponse{stdout: []byte("not a repository list\n")},
			wantText: "parse repositories",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &Client{
				runner: &fakeRunner{responses: []fakeResponse{test.response}},
				path:   "/usr/bin/dnf",
			}

			got, err := client.Repositories(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("Repositories() error = %v, want text %q", err, test.wantText)
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("Repositories() error = %v, want cause %v", err, test.wantCause)
			}
			if got != nil {
				t.Fatalf("Repositories() = %#v, want nil", got)
			}
		})
	}
}

func TestUpdatesRequestsLatestCandidate(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{{}}}
	client := &Client{
		runner: runner,
		path:   "/usr/bin/dnf",
	}

	_, err := client.Updates(context.Background())
	if err != nil {
		t.Fatalf("Updates() error = %v", err)
	}

	if !slices.Contains(runner.requests[0].Args, "--latest-limit=1") {
		t.Fatalf(
			"Updates() arguments = %q, want --latest-limit=1",
			runner.requests[0].Args,
		)
	}
}

func TestNewAtPathsValidatesConfiguration(t *testing.T) {
	t.Parallel()

	commands := RebootCommands{
		RPM:   "/usr/bin/rpm",
		Uname: "/usr/bin/uname",
	}
	tests := []struct {
		name     string
		runner   Runner
		path     string
		commands RebootCommands
		wantErr  string
	}{
		{name: "runner required", path: "/usr/bin/dnf", commands: commands, wantErr: "runner is required"},
		{name: "dnf path required", runner: &fakeRunner{}, commands: commands, wantErr: "dnf path is required"},
		{name: "rpm path required", runner: &fakeRunner{}, path: "/usr/bin/dnf", commands: RebootCommands{Uname: commands.Uname}, wantErr: "rpm path is required"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewAtPaths(test.runner, test.path, test.commands)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("NewAtPaths() error = %v, want %q", err, test.wantErr)
			}
		})
	}
}

func TestUpdatesClassifiesWithSecurityPrecedence(t *testing.T) {
	t.Parallel()

	base := []byte(
		"security|0|2.0|1|x86_64|baseos\n" +
			"bugfix|0|2.0|1|x86_64|baseos\n" +
			"both|0|2.0|1|x86_64|baseos\n" +
			"mismatch|0|2.0|1|x86_64|baseos\n" +
			"enhancement|0|2.0|1|x86_64|baseos\n" +
			"other|0|2.0|1|x86_64|third-party\n",
	)
	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: base},
			{stdout: []byte(
				"security|0|2.0|1|x86_64|baseos\n" +
					"both|0|2.0|1|x86_64|baseos\n" +
					"mismatch|0|1.9|1|x86_64|baseos\n",
			)},
			{stdout: []byte(
				"bugfix|0|2.0|1|x86_64|baseos\n" +
					"both|0|2.0|1|x86_64|baseos\n",
			)},
			{stdout: []byte(
				"enhancement|0|2.0|1|x86_64|baseos\n" +
					"both|0|2.0|1|x86_64|baseos\n",
			)},
		},
	}
	client := &Client{
		runner: runner,
		path:   "/usr/bin/dnf",
	}

	updates, err := client.Updates(context.Background())
	if err != nil {
		t.Fatalf("Updates() error = %v", err)
	}

	wantTypes := map[string]UpdateType{
		"security":    UpdateTypeSecurity,
		"bugfix":      UpdateTypeBugfix,
		"both":        UpdateTypeSecurity,
		"mismatch":    UpdateTypeOther,
		"enhancement": UpdateTypeEnhancement,
		"other":       UpdateTypeOther,
	}
	for _, update := range updates {
		if got, want := update.Type, wantTypes[update.Name]; got != want {
			t.Errorf("%s type = %d, want %d", update.Name, got, want)
		}
	}

	if len(runner.requests) != 4 {
		t.Fatalf("Updates() ran %d queries, want 4", len(runner.requests))
	}

	for _, request := range runner.requests {
		if !slices.Contains(request.Args, "--setopt=*.skip_if_unavailable=False") {
			t.Errorf(
				"update query arguments = %q, want strict unavailable-repository policy",
				request.Args,
			)
		}
	}

	for _, request := range runner.requests[1:] {
		if !strings.Contains(strings.Join(request.Args, " "), "--latest-limit=1") {
			t.Errorf("classification query arguments = %q, want latest limit", request.Args)
		}
	}
}

func TestUpdatesFailsWhenClassificationFails(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		responses []fakeResponse
		wantErr   string
	}{
		{
			name: "security",
			responses: []fakeResponse{
				{stdout: []byte("package|0|2.0|1|x86_64|baseos\n")},
				{err: errors.New("classification unavailable")},
			},
			wantErr: "query security updates",
		},
		{
			name: "bugfix",
			responses: []fakeResponse{
				{stdout: []byte("package|0|2.0|1|x86_64|baseos\n")},
				{},
				{err: errors.New("classification unavailable")},
			},
			wantErr: "query bugfix updates",
		},
		{
			name: "enhancement",
			responses: []fakeResponse{
				{stdout: []byte("package|0|2.0|1|x86_64|baseos\n")},
				{},
				{},
				{err: errors.New("classification unavailable")},
			},
			wantErr: "query enhancement updates",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			runner := &fakeRunner{responses: testCase.responses}
			client := &Client{
				runner: runner,
				path:   "/usr/bin/dnf",
			}

			updates, err := client.Updates(context.Background())
			if err == nil || !strings.Contains(err.Error(), testCase.wantErr) {
				t.Fatalf("Updates() error = %v, want %q", err, testCase.wantErr)
			}
			if updates != nil {
				t.Fatalf("Updates() = %#v, want nil on incomplete classification", updates)
			}
		})
	}
}

func TestUpdatesFailsWhenRepositoryIsUnavailable(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: []fakeResponse{{err: errors.New("repository unavailable")}},
	}
	client := &Client{
		runner: runner,
		path:   "/usr/bin/dnf",
	}

	updates, err := client.Updates(context.Background())
	if err == nil || !strings.Contains(err.Error(), "query updates") {
		t.Fatalf("Updates() error = %v, want unavailable repository failure", err)
	}
	if updates != nil {
		t.Fatalf("Updates() = %#v, want nil when a repository is unavailable", updates)
	}
	if !slices.Contains(
		runner.requests[0].Args,
		"--setopt=*.skip_if_unavailable=False",
	) {
		t.Fatalf(
			"update query arguments = %q, want strict unavailable-repository policy",
			runner.requests[0].Args,
		)
	}
}
