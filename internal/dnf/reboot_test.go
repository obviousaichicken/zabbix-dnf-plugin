//nolint:testpackage // reboot tests verify internal command and parsing behavior.
package dnf

import (
	"context"
	"errors"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

type rebootResponse struct {
	result command.Result
	err    error
}

type rebootRunner struct {
	responses []rebootResponse
	requests  []command.Request
}

func (r *rebootRunner) Run(
	_ context.Context,
	request command.Request,
) (command.Result, error) {
	r.requests = append(r.requests, request)
	response := r.responses[len(r.requests)-1]

	return response.result, response.err
}

func TestRebootCheckerFallsBackToKernelAfterSensitivePackages(t *testing.T) {
	t.Parallel()

	runner := &rebootRunner{
		responses: []rebootResponse{
			{result: command.Result{Stdout: []byte("bash|99\n")}},
			{result: command.Result{Stdout: []byte("5.14.0-570.28.1.el9_6.x86_64\n")}},
			{result: command.Result{Stdout: []byte(
				"kernel-core|5.14.0-570.28.1.el9_6.x86_64\n" +
					"kernel-core|5.14.0-570.30.1.el9_6.x86_64\n",
			)}},
		},
	}
	checker, err := NewRebootChecker(runner, RebootCommands{
		RPM:   "/usr/bin/rpm",
		Uname: "/usr/bin/uname",
	})
	if err != nil {
		t.Fatalf("NewRebootChecker() error = %v", err)
	}
	checker.bootTime = func() (int64, error) {
		return 100, nil
	}

	pending, err := checker.Pending(context.Background())
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}
	if !pending {
		t.Fatal("Pending() = false, want true")
	}
	if len(runner.requests) != 3 {
		t.Fatalf("Pending() ran %d commands, want 3", len(runner.requests))
	}
	if runner.requests[0].Name != "/usr/bin/rpm" {
		t.Fatalf("first reboot request = %#v, want rpm", runner.requests[0])
	}
}

func TestRebootCheckerDetectsRebootSensitivePackage(t *testing.T) {
	t.Parallel()

	runner := &rebootRunner{
		responses: []rebootResponse{{
			result: command.Result{Stdout: []byte("glibc|101\n")},
		}},
	}
	checker, err := NewRebootChecker(runner, RebootCommands{
		RPM:   "/usr/bin/rpm",
		Uname: "/usr/bin/uname",
	})
	if err != nil {
		t.Fatalf("NewRebootChecker() error = %v", err)
	}
	checker.bootTime = func() (int64, error) {
		return 100, nil
	}

	pending, err := checker.Pending(context.Background())
	if err != nil {
		t.Fatalf("Pending() error = %v", err)
	}
	if !pending {
		t.Fatal("Pending() = false, want true")
	}
	if len(runner.requests) != 1 {
		t.Fatalf("Pending() ran %d commands, want 1", len(runner.requests))
	}
}

func TestLookupRebootCommands(t *testing.T) {
	t.Parallel()

	lookupErr := errors.New("command not found")
	tests := []struct {
		name    string
		lookup  func(string) (string, error)
		want    RebootCommands
		wantErr error
	}{
		{
			name: "all commands found",
			lookup: func(name string) (string, error) {
				return "/usr/bin/" + name, nil
			},
			want: RebootCommands{
				RPM:   "/usr/bin/rpm",
				Uname: "/usr/bin/uname",
			},
		},
		{
			name: "rpm missing",
			lookup: func(name string) (string, error) {
				if name == "rpm" {
					return "", lookupErr
				}

				return "/usr/bin/" + name, nil
			},
			wantErr: lookupErr,
		},
		{
			name: "uname missing",
			lookup: func(name string) (string, error) {
				if name == "uname" {
					return "", lookupErr
				}

				return "/usr/bin/" + name, nil
			},
			wantErr: lookupErr,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := LookupRebootCommands(test.lookup)
			if test.wantErr != nil {
				if err == nil || !errors.Is(err, test.wantErr) {
					t.Fatalf("LookupRebootCommands() error = %v, want %v", err, test.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("LookupRebootCommands() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("LookupRebootCommands() = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestNewRebootCheckerValidatesConfiguration(t *testing.T) {
	t.Parallel()

	validCommands := RebootCommands{
		RPM:   "/usr/bin/rpm",
		Uname: "/usr/bin/uname",
	}
	tests := []struct {
		name     string
		runner   Runner
		commands RebootCommands
		wantErr  error
	}{
		{name: "runner required", commands: validCommands, wantErr: errRebootRunnerRequired},
		{name: "rpm path required", runner: &rebootRunner{}, commands: RebootCommands{Uname: validCommands.Uname}, wantErr: errRPMPathRequired},
		{name: "uname path required", runner: &rebootRunner{}, commands: RebootCommands{RPM: validCommands.RPM}, wantErr: errUnamePathRequired},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := NewRebootChecker(test.runner, test.commands)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("NewRebootChecker() error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestRebootCheckerReturnsPackageQueryError(t *testing.T) {
	t.Parallel()

	queryErr := errors.New("rpm unavailable")
	runner := &rebootRunner{
		responses: []rebootResponse{{
			result: command.Result{
				ExitCode: 1,
				Stderr:   []byte("permission denied"),
			},
			err: queryErr,
		}},
	}
	checker := newTestRebootChecker(t, runner)
	checker.bootTime = func() (int64, error) {
		return 100, nil
	}

	_, err := checker.Pending(context.Background())
	if !errors.Is(err, queryErr) {
		t.Fatalf("Pending() error = %v, want query error", err)
	}

	var commandErr *CommandError
	if !errors.As(err, &commandErr) {
		t.Fatalf("Pending() error = %v, want CommandError", err)
	}
	if commandErr.ExitStatus != 1 {
		t.Fatalf("Pending() CommandError = %#v", commandErr)
	}
}

func TestRebootSensitivePackageInstalledRejectsInvalidInstallTime(t *testing.T) {
	t.Parallel()

	_, err := rebootSensitivePackageInstalled([]byte("glibc|not-a-time\n"), 100)
	if err == nil {
		t.Fatal("rebootSensitivePackageInstalled() expected error")
	}
}

func TestParseBootTime(t *testing.T) {
	t.Parallel()

	bootTime, err := parseBootTime([]byte("cpu  1 2 3\nbtime 1700000000\n"))
	if err != nil {
		t.Fatalf("parseBootTime() error = %v", err)
	}
	if bootTime != 1700000000 {
		t.Fatalf("parseBootTime() = %d, want 1700000000", bootTime)
	}
}

func TestRebootSensitivePackageInstalled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want bool
	}{
		{name: "unrelated package", data: "bash|101\n", want: false},
		{name: "package installed before boot", data: "glibc|100\n", want: false},
		{name: "openssl libraries", data: "openssl-libs|101\n", want: true},
		{name: "gnutls", data: "gnutls|101\n", want: true},
		{name: "real-time kernel handled separately", data: "kernel-rt-core|101\n", want: false},
		{name: "debug kernel handled separately", data: "kernel-debug-core|101\n", want: false},
		{name: "udev", data: "udev|101\n", want: true},
		{name: "firmware package pattern", data: "linux-firmware-whence|101\n", want: true},
		{name: "firmware package suffix", data: "realtek-firmware|101\n", want: true},
		{name: "systemd", data: "systemd|101\n", want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			pending, err := rebootSensitivePackageInstalled([]byte(test.data), 100)
			if err != nil {
				t.Fatalf("rebootSensitivePackageInstalled() error = %v", err)
			}
			if pending != test.want {
				t.Fatalf("rebootSensitivePackageInstalled() = %t, want %t", pending, test.want)
			}
		})
	}
}

func TestIsKernelPackage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		pkg  string
		want bool
	}{
		{name: "standard kernel", pkg: "kernel", want: true},
		{name: "standard kernel core", pkg: "kernel-core", want: true},
		{name: "real-time kernel", pkg: "kernel-rt", want: true},
		{name: "real-time kernel core", pkg: "kernel-rt-core", want: true},
		{name: "debug kernel core", pkg: "kernel-debug-core", want: true},
		{name: "kernel modules", pkg: "kernel-modules", want: false},
		{name: "kernel modules core", pkg: "kernel-modules-core", want: false},
		{name: "kernel modules extra", pkg: "kernel-modules-extra", want: false},
		{name: "kernel devel", pkg: "kernel-devel", want: false},
		{name: "kernel tools", pkg: "kernel-tools", want: false},
		{name: "debug kernel meta package", pkg: "kernel-debug", want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := isKernelPackage(test.pkg); got != test.want {
				t.Fatalf("isKernelPackage(%q) = %t, want %t", test.pkg, got, test.want)
			}
		})
	}
}

func TestRebootCheckerFallsBackToInstalledKernel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		running      string
		installed    string
		packageQuery string
		want         bool
	}{
		{
			name:    "running latest RHEL 8 kernel",
			running: "4.18.0-553.40.1.el8_10.x86_64\n",
			installed: "kernel-core|4.18.0-553.39.1.el8_10.x86_64\n" +
				"kernel-core|4.18.0-553.40.1.el8_10.x86_64\n",
			want: false,
		},
		{
			name:    "newer RHEL 9 kernel-core installed",
			running: "5.14.0-570.28.1.el9_6.x86_64\n",
			installed: "kernel-core|5.14.0-570.28.1.el9_6.x86_64\n" +
				"kernel-core|5.14.0-570.30.1.el9_6.x86_64\n",
			want: true,
		},
		{
			name:    "newer real-time kernel-core installed",
			running: "5.14.0-570.28.1.rt.el9_6.x86_64\n",
			installed: "kernel-rt-core|5.14.0-570.28.1.rt.el9_6.x86_64\n" +
				"kernel-rt-core|5.14.0-570.30.1.rt.el9_6.x86_64\n",
			want: true,
		},
		{
			name:    "newer debug kernel-core installed",
			running: "5.14.0-570.28.1.debug.el9_6.x86_64\n",
			installed: "kernel-debug-core|5.14.0-570.28.1.debug.el9_6.x86_64\n" +
				"kernel-debug-core|5.14.0-570.30.1.debug.el9_6.x86_64\n",
			want: true,
		},
		{
			name:    "newer kernel modules core is ignored",
			running: "5.14.0-570.28.1.el9_6.x86_64\n",
			installed: "kernel-modules-core|5.14.0-570.28.1.el9_6.x86_64\n" +
				"kernel-modules-core|5.14.0-570.30.1.el9_6.x86_64\n",
			want: false,
		},
		{
			name:         "older kernel reinstalled later",
			running:      "5.14.0-570.30.1.el9_6.x86_64\n",
			packageQuery: "kernel-core|101\n",
			installed: "kernel-core|5.14.0-570.30.1.el9_6.x86_64\n" +
				"kernel-core|5.14.0-570.9.1.el9_6.x86_64\n",
			want: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			packageQuery := test.packageQuery
			if packageQuery == "" {
				packageQuery = "bash|99\n"
			}
			runner := &rebootRunner{
				responses: []rebootResponse{
					{result: command.Result{Stdout: []byte(packageQuery), ExitCode: 0}},
					{result: command.Result{Stdout: []byte(test.running), ExitCode: 0}},
					{result: command.Result{Stdout: []byte(test.installed), ExitCode: 0}},
				},
			}
			checker := newTestRebootChecker(t, runner)
			checker.bootTime = func() (int64, error) {
				return 100, nil
			}

			pending, err := checker.Pending(context.Background())
			if err != nil {
				t.Fatalf("Pending() error = %v", err)
			}
			if pending != test.want {
				t.Fatalf("Pending() = %t, want %t", pending, test.want)
			}
			if len(runner.requests) != 3 {
				t.Fatalf("Pending() ran %d commands, want 3", len(runner.requests))
			}
		})
	}
}

func newTestRebootChecker(t *testing.T, runner Runner) *RebootChecker {
	t.Helper()

	checker, err := NewRebootChecker(runner, RebootCommands{
		RPM:   "/usr/bin/rpm",
		Uname: "/usr/bin/uname",
	})
	if err != nil {
		t.Fatalf("NewRebootChecker() error = %v", err)
	}

	return checker
}
