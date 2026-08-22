//nolint:testpackage // reboot tests verify internal command and parsing behavior.
package dnf

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRebootCheckerFallsBackToKernelAfterSensitivePackages(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: []byte("bash|99\n")},
			{stdout: []byte("5.14.0-570.28.1.el9_6.x86_64\n")},
			{stdout: []byte(
				"kernel-core|5.14.0-570.28.1.el9_6.x86_64\n" +
					"kernel-core|5.14.0-570.30.1.el9_6.x86_64\n",
			)},
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

	runner := &fakeRunner{
		responses: []fakeResponse{{
			stdout: []byte("glibc|101\n"),
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

func TestClientRebootPending(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: []fakeResponse{{stdout: []byte("glibc|101\n")}},
	}
	checker := newTestRebootChecker(t, runner)
	checker.bootTime = func() (int64, error) {
		return 100, nil
	}
	client := &Client{rebootChecker: checker}

	pending, err := client.RebootPending(context.Background())
	if err != nil {
		t.Fatalf("RebootPending() error = %v", err)
	}
	if !pending {
		t.Fatal("RebootPending() = false, want true")
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
		{name: "rpm path required", runner: &fakeRunner{}, commands: RebootCommands{Uname: validCommands.Uname}, wantErr: errRPMPathRequired},
		{name: "uname path required", runner: &fakeRunner{}, commands: RebootCommands{RPM: validCommands.RPM}, wantErr: errUnamePathRequired},
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
	runner := &fakeRunner{
		responses: []fakeResponse{{
			exitCode: 1,
			stderr:   []byte("permission denied"),
			err:      queryErr,
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

func TestRebootCheckerReturnsBootTimeError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("boot time unavailable")
	checker := newTestRebootChecker(t, &fakeRunner{})
	checker.bootTime = func() (int64, error) {
		return 0, wantErr
	}

	_, err := checker.Pending(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("Pending() error = %v, want %v", err, wantErr)
	}
	if !strings.Contains(err.Error(), "read boot time") {
		t.Fatalf("Pending() error = %v, want boot-time context", err)
	}
}

func TestKernelPendingReturnsErrors(t *testing.T) {
	t.Parallel()

	commandErr := errors.New("kernel command failed")
	tests := []struct {
		name      string
		responses []fakeResponse
		wantCause error
		wantText  string
	}{
		{
			name:      "running kernel query failure",
			responses: []fakeResponse{{err: commandErr}},
			wantCause: commandErr,
			wantText:  "read running kernel",
		},
		{
			name: "installed kernel query failure",
			responses: []fakeResponse{
				{stdout: []byte("5.14.0-570.el9.x86_64\n")},
				{err: commandErr},
			},
			wantCause: commandErr,
			wantText:  "query installed kernels",
		},
		{
			name: "installed kernel parse failure",
			responses: []fakeResponse{
				{stdout: []byte("5.14.0-570.el9.x86_64\n")},
				{stdout: []byte(strings.Repeat("x", 70*1024))},
			},
			wantText: "compare installed kernels",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			checker := newTestRebootChecker(t, &fakeRunner{responses: test.responses})

			_, err := checker.kernelPending(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("kernelPending() error = %v, want text %q", err, test.wantText)
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("kernelPending() error = %v, want cause %v", err, test.wantCause)
			}
		})
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

func TestParseBootTimeRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		data     string
		wantText string
	}{
		{name: "missing btime", data: "cpu  1 2 3\n", wantText: "btime not found"},
		{name: "invalid btime", data: "btime not-a-time\n", wantText: "parse btime"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseBootTime([]byte(test.data))
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("parseBootTime() error = %v, want text %q", err, test.wantText)
			}
		})
	}
}

func TestRebootSensitivePackageInstalled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
		want bool
	}{
		{name: "malformed row ignored", data: "malformed\n", want: false},
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

func TestCompareKernelRelease(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		left  string
		right string
		want  int
	}{
		{name: "equal", left: "5.14.0-570.el9", right: "5.14.0-570.el9", want: 0},
		{name: "newer numeric segment", left: "5.14.0-571.el9", right: "5.14.0-570.el9", want: 1},
		{name: "older numeric segment", left: "5.14.0-569.el9", right: "5.14.0-570.el9", want: -1},
		{name: "numeric after alphabetic", left: "5.14.0-1", right: "5.14.0-a", want: 1},
		{name: "alphabetic before numeric", left: "5.14.0-a", right: "5.14.0-1", want: -1},
		{name: "leading zeroes ignored", left: "5.14.0-00570.el9", right: "5.14.0-570.el9", want: 0},
		{name: "longer numeric segment is newer", left: "5.14.0-1000.el9", right: "5.14.0-999.el9", want: 1},
		{name: "left segment missing", left: "5.14", right: "5.14.1", want: -1},
		{name: "right segment missing", left: "5.14.1", right: "5.14", want: 1},
		{name: "alphabetic segment ordering", left: "5.14.0-debug", right: "5.14.0-alpha", want: 1},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := compareKernelRelease(test.left, test.right); got != test.want {
				t.Fatalf(
					"compareKernelRelease(%q, %q) = %d, want %d",
					test.left,
					test.right,
					got,
					test.want,
				)
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
			name:    "newer different kernel flavor is ignored",
			running: "5.14.0-570.28.1.el9_6.x86_64\n",
			installed: "kernel-core|5.14.0-570.28.1.el9_6.x86_64\n" +
				"kernel-rt-core|5.14.0-570.30.1.rt.el9_6.x86_64\n",
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
			runner := &fakeRunner{
				responses: []fakeResponse{
					{stdout: []byte(packageQuery)},
					{stdout: []byte(test.running)},
					{stdout: []byte(test.installed)},
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
