//nolint:testpackage // runner tests exercise accepted process exit behavior directly.
package command

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

const (
	helperProcessEnv      = "GO_WANT_COMMAND_HELPER_PROCESS"
	helperProcessBlockEnv = "GO_WANT_BLOCKING_COMMAND_HELPER_PROCESS"
)

func TestRunnerAcceptsConfiguredExitCode(t *testing.T) {
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}

	result, err := (Runner{}).Run(context.Background(), Request{
		Name:              executable,
		Args:              []string{"-test.run=^TestRunnerExitOneHelper$"},
		AcceptedExitCodes: []int{1},
		Env:               map[string]string{helperProcessEnv: "1"},
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.ExitCode != 1 {
		t.Fatalf("Run().ExitCode = %d, want 1", result.ExitCode)
	}
}

func TestRunnerRejectsUnconfiguredExitCode(t *testing.T) {
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}

	result, err := (Runner{}).Run(context.Background(), Request{
		Name:              executable,
		Args:              []string{"-test.run=^TestRunnerExitOneHelper$"},
		AcceptedExitCodes: nil,
		Env:               map[string]string{helperProcessEnv: "1"},
	})
	if err == nil {
		t.Fatal("Run() expected error")
	}
	if result.ExitCode != 1 {
		t.Fatalf("Run().ExitCode = %d, want 1", result.ExitCode)
	}
}

func TestRunnerStopsCommandAtContextDeadline(t *testing.T) {
	t.Parallel()

	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()

	_, err = (Runner{}).Run(ctx, Request{
		Name: executable,
		Args: []string{"-test.run=^TestRunnerBlockingHelper$"},
		Env:  map[string]string{helperProcessBlockEnv: "1"},
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Run() error = %v, want context deadline exceeded", err)
	}
	if duration := time.Since(started); duration >= 2*time.Second {
		t.Fatalf("Run() returned after %s, want prompt process cancellation", duration)
	}
}

//nolint:paralleltest // this helper runs only in a subprocess and exits immediately.
func TestRunnerExitOneHelper(_ *testing.T) {
	if os.Getenv(helperProcessEnv) != "1" {
		return
	}

	os.Exit(1)
}

//nolint:paralleltest // this helper runs only in a subprocess and waits to be killed.
func TestRunnerBlockingHelper(_ *testing.T) {
	if os.Getenv(helperProcessBlockEnv) != "1" {
		return
	}

	time.Sleep(10 * time.Second)
}
