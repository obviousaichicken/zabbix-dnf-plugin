// Package command executes external commands and captures their output.
package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

const (
	maxStdoutBytes = 8 << 20
	maxStderrBytes = 256 << 10

	// Bound the wait for inherited output pipes after cancellation.
	commandWaitDelay = 100 * time.Millisecond
)

var (
	errCommandNameRequired = errors.New("command name is required")
	errCommandOutputLimit  = errors.New("command output limit exceeded")
)

// Request is a command invocation.
type Request struct {
	Name string
	Args []string

	// AcceptedExitCodes permits documented non-zero success statuses.
	AcceptedExitCodes []int

	// Env overrides the inherited process environment for this command.
	Env map[string]string
}

// Result contains command output and exit status.
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
}

// Runner executes commands.
type Runner struct{}

// Run executes a command and captures its output.
func (Runner) Run(ctx context.Context, req Request) (Result, error) {
	if req.Name == "" {
		return Result{Stdout: nil, Stderr: nil, ExitCode: -1}, errCommandNameRequired
	}

	//nolint:gosec // command execution is the purpose of this package.
	cmd := exec.CommandContext(ctx, req.Name, req.Args...)
	configureCommandCancellation(cmd)
	cmd.Env = mergeEnv(os.Environ(), req.Env)

	stdout := newCappedBuffer(maxStdoutBytes)
	stderr := newCappedBuffer(maxStderrBytes)

	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()

	result := Result{
		Stdout:   append([]byte(nil), stdout.Bytes()...),
		Stderr:   append([]byte(nil), stderr.Bytes()...),
		ExitCode: -1,
	}

	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}

	// Command cancellation kills the process tree when the platform supports it.
	// Return the context error rather than only "signal: killed".
	ctxErr := ctx.Err()
	if ctxErr != nil {
		return result, fmt.Errorf("command context: %w", ctxErr)
	}

	if stdout.Overflowed() {
		return result, fmt.Errorf(
			"stdout exceeds %d bytes: %w",
			maxStdoutBytes,
			errCommandOutputLimit,
		)
	}

	if stderr.Overflowed() {
		return result, fmt.Errorf(
			"stderr exceeds %d bytes: %w",
			maxStderrBytes,
			errCommandOutputLimit,
		)
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && acceptsExitCode(req.AcceptedExitCodes, result.ExitCode) {
			return result, nil
		}

		return result, fmt.Errorf("run command: %w", err)
	}

	return result, nil
}

func acceptsExitCode(accepted []int, exitCode int) bool {
	for _, candidate := range accepted {
		if candidate == exitCode {
			return true
		}
	}

	return false
}

type cappedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow bool
}

func newCappedBuffer(limit int) *cappedBuffer {
	return &cappedBuffer{
		buffer:   bytes.Buffer{},
		limit:    limit,
		overflow: false,
	}
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := b.limit - b.buffer.Len()

	if remaining <= 0 {
		b.overflow = b.overflow || written > 0

		return written, nil
	}

	if len(data) > remaining {
		data = data[:remaining]
		b.overflow = true
	}

	_, _ = b.buffer.Write(data)

	return written, nil
}

func (b *cappedBuffer) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *cappedBuffer) Overflowed() bool {
	return b.overflow
}

func mergeEnv(base []string, overrides map[string]string) []string {
	if len(overrides) == 0 {
		return append([]string(nil), base...)
	}

	env := make([]string, 0, len(base)+len(overrides))
	index := make(map[string]int, len(base))

	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}

		if i, exists := index[key]; exists {
			env[i] = entry

			continue
		}

		index[key] = len(env)
		env = append(env, entry)
	}

	// Sorting isn't required by exec, but makes the resulting environment
	// deterministic for tests.
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, key)
	}

	sort.Strings(keys)

	for _, key := range keys {
		entry := key + "=" + overrides[key]

		if i, exists := index[key]; exists {
			env[i] = entry

			continue
		}

		index[key] = len(env)
		env = append(env, entry)
	}

	return env
}
