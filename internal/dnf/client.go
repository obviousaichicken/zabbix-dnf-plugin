// Package dnf collects repositories and package updates using DNF.
package dnf

import (
	"context"
	"errors"
	"fmt"
	"os/exec"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

var errRunnerRequired = errors.New("runner is required")

// Client runs DNF commands and parses output.
type Client struct {
	runner        Runner
	path          string
	rebootChecker *RebootChecker
}

// Collect returns one complete DNF package snapshot in the established stage order.
func (c *Client) Collect(ctx context.Context) (packageinfo.Snapshot, error) {
	repositories, err := c.Repositories(ctx)
	if err != nil {
		return packageinfo.Snapshot{}, fmt.Errorf("collect repositories: %w", err)
	}

	updates, err := c.Updates(ctx)
	if err != nil {
		return packageinfo.Snapshot{}, fmt.Errorf("collect updates: %w", err)
	}
	for index := range updates {
		setUpdateIdentity(&updates[index])
	}

	rebootPending, err := c.RebootPending(ctx)
	if err != nil {
		return packageinfo.Snapshot{}, fmt.Errorf("collect reboot status: %w", err)
	}

	lastUpdate, err := c.LastUpdate(ctx)
	if err != nil {
		return packageinfo.Snapshot{}, fmt.Errorf("collect last update: %w", err)
	}

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
		Repositories:  repositories,
		Updates:       updates,
		RebootPending: rebootPending,
		LastUpdate:    lastUpdate,
	}, nil
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
