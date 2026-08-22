//nolint:testpackage // shared fake runner supports white-box dnf tests.
package dnf

import (
	"context"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

type fakeResponse struct {
	stdout   []byte
	stderr   []byte
	exitCode int
	err      error
}

type fakeRunner struct {
	responses []fakeResponse
	requests  []command.Request
}

func (r *fakeRunner) Run(
	_ context.Context,
	request command.Request,
) (command.Result, error) {
	r.requests = append(r.requests, request)
	response := r.responses[len(r.requests)-1]

	return command.Result{
		Stdout:   response.stdout,
		Stderr:   response.stderr,
		ExitCode: response.exitCode,
	}, response.err
}
