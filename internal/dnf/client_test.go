//nolint:testpackage // constructing Client directly isolates command argument behavior.
package dnf

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

type recordingRunner struct {
	request command.Request
}

func (r *recordingRunner) Run(
	_ context.Context,
	request command.Request,
) (command.Result, error) {
	r.request = request

	return command.Result{
		Stdout:   nil,
		Stderr:   nil,
		ExitCode: 0,
	}, nil
}

func TestUpdatesRequestsLatestCandidate(t *testing.T) {
	t.Parallel()

	runner := new(recordingRunner)
	client := &Client{
		runner: runner,
		path:   "/usr/bin/dnf",
	}

	_, err := client.Updates(context.Background())
	if err != nil {
		t.Fatalf("Updates() error = %v", err)
	}

	if !slices.Contains(runner.request.Args, "--latest-limit=1") {
		t.Fatalf(
			"Updates() arguments = %q, want --latest-limit=1",
			runner.request.Args,
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
		{name: "dnf path required", runner: &recordingRunner{}, commands: commands, wantErr: "dnf path is required"},
		{name: "rpm path required", runner: &recordingRunner{}, path: "/usr/bin/dnf", commands: RebootCommands{Uname: commands.Uname}, wantErr: "rpm path is required"},
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

type updateClassificationRunner struct {
	outputs  [][]byte
	errors   []error
	requests []command.Request
}

func (r *updateClassificationRunner) Run(
	_ context.Context,
	request command.Request,
) (command.Result, error) {
	r.requests = append(r.requests, request)
	output := r.outputs[len(r.requests)-1]
	var err error
	if len(r.errors) >= len(r.requests) {
		err = r.errors[len(r.requests)-1]
	}

	return command.Result{
		Stdout:   output,
		Stderr:   nil,
		ExitCode: 0,
	}, err
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
	runner := &updateClassificationRunner{
		outputs: [][]byte{
			base,
			[]byte(
				"security|0|2.0|1|x86_64|baseos\n" +
					"both|0|2.0|1|x86_64|baseos\n" +
					"mismatch|0|1.9|1|x86_64|baseos\n",
			),
			[]byte(
				"bugfix|0|2.0|1|x86_64|baseos\n" +
					"both|0|2.0|1|x86_64|baseos\n",
			),
			[]byte(
				"enhancement|0|2.0|1|x86_64|baseos\n" +
					"both|0|2.0|1|x86_64|baseos\n",
			),
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
		name    string
		errors  []error
		wantErr string
	}{
		{
			name:    "security",
			errors:  []error{nil, errors.New("classification unavailable")},
			wantErr: "query security updates",
		},
		{
			name:    "bugfix",
			errors:  []error{nil, nil, errors.New("classification unavailable")},
			wantErr: "query bugfix updates",
		},
		{
			name:    "enhancement",
			errors:  []error{nil, nil, nil, errors.New("classification unavailable")},
			wantErr: "query enhancement updates",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			runner := &updateClassificationRunner{
				outputs: [][]byte{
					[]byte("package|0|2.0|1|x86_64|baseos\n"),
					nil,
					nil,
					nil,
				},
				errors: testCase.errors,
			}
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

	runner := &updateClassificationRunner{
		outputs: [][]byte{nil},
		errors:  []error{errors.New("repository unavailable")},
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
