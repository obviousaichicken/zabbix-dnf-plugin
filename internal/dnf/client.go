// Package dnf collects repositories and package updates using DNF.
package dnf

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

var errRunnerRequired = errors.New("runner is required")

// Client runs DNF commands and parses output.
type Client struct {
	runner        Runner
	path          string
	rebootChecker *RebootChecker
}

// New creates a DNF client and resolves its command paths.
func New(runnerInstance Runner) (*Client, error) {
	if runnerInstance == nil {
		return nil, errRunnerRequired
	}

	path, err := exec.LookPath("dnf")
	if err != nil {
		return nil, fmt.Errorf("find dnf: %w", err)
	}

	rebootCommands, err := LookupRebootCommands(exec.LookPath)
	if err != nil {
		return nil, fmt.Errorf("find reboot commands: %w", err)
	}

	return NewAtPaths(runnerInstance, path, rebootCommands)
}

// NewAtPaths creates a DNF client from resolved command paths.
func NewAtPaths(
	runnerInstance Runner,
	path string,
	rebootCommands RebootCommands,
) (*Client, error) {
	if runnerInstance == nil {
		return nil, errRunnerRequired
	}
	if path == "" {
		return nil, errors.New("dnf path is required")
	}

	rebootChecker, err := NewRebootChecker(
		runnerInstance,
		rebootCommands,
	)
	if err != nil {
		return nil, fmt.Errorf("configure reboot checker: %w", err)
	}

	return &Client{
		runner:        runnerInstance,
		path:          path,
		rebootChecker: rebootChecker,
	}, nil
}

func (c *Client) run(ctx context.Context, args ...string) (command.Result, error) {
	args = append([]string{"--assumeno"}, args...)

	return runCommand(
		ctx,
		c.runner,
		c.path,
		args,
		nil,
	)
}
