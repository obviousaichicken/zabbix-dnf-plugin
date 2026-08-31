package apt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"sort"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

const installedQueryFormat = "${binary:Package}|${Architecture}|${Version}|${db:Status-Status}\\n"

var errRunnerRequired = errors.New("runner is required")

// Runner executes APT and dpkg commands.
type Runner interface {
	Run(context.Context, command.Request) (command.Result, error)
}

// CommandPaths contains the resolved executables used by the APT collector.
type CommandPaths struct {
	APTGet    string
	APTCache  string
	DPKGQuery string
	DPKG      string
}

// PackageData contains the repository/update portion of an APT snapshot.
// Reboot and history data are added by the later collection stage.
type PackageData struct {
	Repositories []packageinfo.Repository
	Updates      []packageinfo.Update
	Metadata     packageinfo.Metadata
}

// Client runs bounded, read-only APT package collection.
type Client struct {
	runner       Runner
	paths        CommandPaths
	stat         func(string) (fs.FileInfo, error)
	now          func() time.Time
	rebootMarker string
	history      *HistoryReader
}

var _ interface {
	Collect(context.Context) (packageinfo.Snapshot, error)
} = (*Client)(nil)

// New constructs an APT client after resolving every required executable.
func New(runner Runner) (*Client, error) {
	if runner == nil {
		return nil, errRunnerRequired
	}

	paths := CommandPaths{}
	commands := []struct {
		name        string
		destination *string
	}{
		{name: "apt-get", destination: &paths.APTGet},
		{name: "apt-cache", destination: &paths.APTCache},
		{name: "dpkg-query", destination: &paths.DPKGQuery},
		{name: "dpkg", destination: &paths.DPKG},
	}
	for _, candidate := range commands {
		path, err := exec.LookPath(candidate.name)
		if err != nil {
			return nil, fmt.Errorf("find %s: %w", candidate.name, err)
		}
		*candidate.destination = path
	}

	return NewAtPaths(runner, paths)
}

// NewAtPaths constructs an APT client from already-resolved executables.
func NewAtPaths(runner Runner, paths CommandPaths) (*Client, error) {
	return newClient(runner, paths, os.Stat, time.Now)
}

func newClientForTest(
	runner Runner,
	paths CommandPaths,
	stat func(string) (fs.FileInfo, error),
	now func() time.Time,
) (*Client, error) {
	return newClient(runner, paths, stat, now)
}

func newClient(
	runner Runner,
	paths CommandPaths,
	stat func(string) (fs.FileInfo, error),
	now func() time.Time,
) (*Client, error) {
	if runner == nil {
		return nil, errRunnerRequired
	}
	for _, required := range []struct {
		name string
		path string
	}{
		{name: "apt-get", path: paths.APTGet},
		{name: "apt-cache", path: paths.APTCache},
		{name: "dpkg-query", path: paths.DPKGQuery},
		{name: "dpkg", path: paths.DPKG},
	} {
		if required.path == "" {
			return nil, fmt.Errorf("%s path is required", required.name)
		}
	}
	if stat == nil {
		return nil, errors.New("filesystem stat function is required")
	}
	if now == nil {
		return nil, errors.New("clock function is required")
	}

	history, err := newHistoryReader(osHistoryFileSystem{}, defaultHistoryDirectory, time.Local)
	if err != nil {
		return nil, fmt.Errorf("configure APT history reader: %w", err)
	}

	return &Client{
		runner:       runner,
		paths:        paths,
		stat:         stat,
		now:          now,
		rebootMarker: defaultRebootMarker,
		history:      history,
	}, nil
}

func newClientWithSystemForTest(
	runner Runner,
	paths CommandPaths,
	stat func(string) (fs.FileInfo, error),
	now func() time.Time,
	historyFileSystem historyFileSystem,
	historyDirectory string,
	rebootMarker string,
	location *time.Location,
) (*Client, error) {
	client, err := newClient(runner, paths, stat, now)
	if err != nil {
		return nil, err
	}
	history, err := newHistoryReaderForTest(historyFileSystem, historyDirectory, location)
	if err != nil {
		return nil, err
	}
	if rebootMarker == "" {
		return nil, errors.New("reboot marker path is required")
	}
	client.history = history
	client.rebootMarker = rebootMarker

	return client, nil
}

// Collect returns one complete, uncached APT package snapshot.
func (client *Client) Collect(ctx context.Context) (packageinfo.Snapshot, error) {
	data, err := client.Packages(ctx)
	if err != nil {
		return packageinfo.Snapshot{}, fmt.Errorf("collect APT packages: %w", err)
	}
	rebootPending, err := client.RebootPending(ctx)
	if err != nil {
		return packageinfo.Snapshot{}, fmt.Errorf("collect APT reboot status: %w", err)
	}
	lastUpdate, err := client.LastUpdate(ctx)
	if err != nil {
		return packageinfo.Snapshot{}, fmt.Errorf("collect APT update history: %w", err)
	}

	return packageinfo.Snapshot{
		Backend: packageinfo.BackendAPT,
		Capabilities: packageinfo.Capabilities{
			Classification: packageinfo.ClassificationCapabilities{
				Security:    packageinfo.CapabilitySupported,
				Bugfix:      packageinfo.CapabilityUnsupported,
				Enhancement: packageinfo.CapabilityUnsupported,
				Other:       packageinfo.CapabilitySupported,
			},
			RepositoryAttribution: packageinfo.CapabilitySupported,
			RebootDetection:       packageinfo.CapabilitySupported,
			LastUpdate:            packageinfo.CapabilityBestEffort,
			MetadataAge:           packageinfo.CapabilitySupported,
		},
		Metadata:      data.Metadata,
		Repositories:  data.Repositories,
		Updates:       data.Updates,
		RebootPending: rebootPending,
		LastUpdate:    lastUpdate,
	}, nil
}

// Packages collects enabled repositories, exact candidate policies, pending
// updates, and the age of the oldest participating index.
func (client *Client) Packages(ctx context.Context) (PackageData, error) {
	indexResult, err := client.run(
		ctx,
		"apt-get indextargets",
		client.paths.APTGet,
		[]string{"indextargets"},
		nil,
	)
	if err != nil {
		return PackageData{}, fmt.Errorf("list APT repository indexes: %w", err)
	}
	indexes, err := ParseRepositoryIndexes(indexResult.Stdout)
	if err != nil {
		return PackageData{}, err
	}
	metadata, err := client.indexMetadata(ctx, indexes.Targets)
	if err != nil {
		return PackageData{}, fmt.Errorf("collect APT index metadata: %w", err)
	}

	installedResult, err := client.run(
		ctx,
		"dpkg-query installed packages",
		client.paths.DPKGQuery,
		[]string{"--show", "--showformat=" + installedQueryFormat},
		nil,
	)
	if err != nil {
		return PackageData{}, fmt.Errorf("list installed packages: %w", err)
	}
	installed, err := ParseInstalledPackages(installedResult.Stdout)
	if err != nil {
		return PackageData{}, err
	}

	policies, err := client.packagePolicies(ctx, installed, indexes)
	if err != nil {
		return PackageData{}, err
	}
	updates, err := client.pendingUpdates(ctx, installed, policies)
	if err != nil {
		return PackageData{}, err
	}

	return PackageData{
		Repositories: indexes.Repositories,
		Updates:      updates,
		Metadata:     metadata,
	}, nil
}

func (client *Client) packagePolicies(
	ctx context.Context,
	installed []InstalledPackage,
	indexes RepositoryIndexes,
) ([]PackagePolicy, error) {
	argumentBatches, err := BatchPolicyArguments(installed)
	if err != nil {
		return nil, err
	}
	policies := make([]PackagePolicy, 0, len(installed))
	offset := 0
	for _, arguments := range argumentBatches {
		args := make([]string, 1, len(arguments)+1)
		args[0] = "policy"
		args = append(args, arguments...)
		result, runErr := client.run(
			ctx,
			fmt.Sprintf("apt-cache policy (%d packages)", len(arguments)),
			client.paths.APTCache,
			args,
			nil,
		)
		if runErr != nil {
			return nil, fmt.Errorf("query APT package policy: %w", runErr)
		}

		requested := installed[offset : offset+len(arguments)]
		batchPolicies, parseErr := ParsePackagePolicies(result.Stdout, requested, indexes)
		if parseErr != nil {
			return nil, parseErr
		}
		policies = append(policies, batchPolicies...)
		offset += len(arguments)
	}
	if offset != len(installed) {
		return nil, errors.New("APT policy batching did not cover every installed package")
	}

	sort.Slice(policies, func(left, right int) bool {
		if policies[left].Name != policies[right].Name {
			return policies[left].Name < policies[right].Name
		}

		return policies[left].Architecture < policies[right].Architecture
	})

	return policies, nil
}

func (client *Client) pendingUpdates(
	ctx context.Context,
	installed []InstalledPackage,
	policies []PackagePolicy,
) ([]packageinfo.Update, error) {
	installedByKey := make(map[string]InstalledPackage, len(installed))
	for _, pkg := range installed {
		installedByKey[packageKey(pkg.Name, pkg.Architecture)] = pkg
	}
	if len(policies) != len(installedByKey) {
		return nil, errors.New("APT policy count does not match installed-package count")
	}

	updates := make([]packageinfo.Update, 0)
	seen := make(map[string]struct{}, len(policies))
	for _, policy := range policies {
		key := packageKey(policy.Name, policy.Architecture)
		pkg, exists := installedByKey[key]
		if !exists {
			return nil, errors.New("APT policy references an unknown installed package")
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, errors.New("APT policy contains a duplicate package")
		}
		seen[key] = struct{}{}
		if policy.Installed == nil || policy.Installed.Full != pkg.Version.Full {
			return nil, fmt.Errorf("package state changed while collecting %s:%s", pkg.Name, pkg.Architecture)
		}
		if policy.Candidate == nil || policy.Candidate.Full == pkg.Version.Full {
			continue
		}

		newer, err := client.candidateIsNewer(ctx, pkg, *policy.Candidate)
		if err != nil {
			return nil, err
		}
		if !newer {
			continue
		}
		source, err := preferredCandidateSource(policy.CandidateSources)
		if err != nil {
			return nil, fmt.Errorf("select candidate source for %s:%s: %w", pkg.Name, pkg.Architecture, err)
		}

		updateType := packageinfo.UpdateTypeOther
		if winningCandidateIsSecurity(policy.CandidateSources) {
			updateType = packageinfo.UpdateTypeSecurity
		}
		update := packageinfo.Update{
			Name:         pkg.Name,
			Epoch:        policy.Candidate.Epoch,
			Version:      policy.Candidate.Version,
			Release:      policy.Candidate.Release,
			Arch:         pkg.Architecture,
			RepositoryID: source.RepositoryID,
			Type:         updateType,
		}
		packageinfo.SetIdentity(packageinfo.BackendAPT, &update)
		updates = append(updates, update)
	}

	sort.Slice(updates, func(left, right int) bool {
		if updates[left].RepositoryID != updates[right].RepositoryID {
			return updates[left].RepositoryID < updates[right].RepositoryID
		}
		if updates[left].Name != updates[right].Name {
			return updates[left].Name < updates[right].Name
		}

		return updates[left].Arch < updates[right].Arch
	})

	return updates, nil
}

func (client *Client) candidateIsNewer(
	ctx context.Context,
	pkg InstalledPackage,
	candidate DebianVersion,
) (bool, error) {
	result, err := client.run(
		ctx,
		"dpkg compare package versions",
		client.paths.DPKG,
		[]string{"--compare-versions", candidate.Full, "gt", pkg.Version.Full},
		[]int{1},
	)
	if err != nil {
		return false, fmt.Errorf("compare package versions for %s:%s: %w", pkg.Name, pkg.Architecture, err)
	}
	switch result.ExitCode {
	case 0:
		return true, nil
	case 1:
		return false, nil
	default:
		return false, errors.New("dpkg --compare-versions returned an unexpected exit status")
	}
}

func preferredCandidateSource(sources []PolicySource) (PolicySource, error) {
	if len(sources) == 0 {
		return PolicySource{}, errors.New("candidate has no repository sources")
	}

	preferred := sources[0]
	for _, source := range sources[1:] {
		if source.Priority > preferred.Priority {
			preferred = source
		}
	}

	return preferred, nil
}

func winningCandidateIsSecurity(sources []PolicySource) bool {
	if len(sources) == 0 {
		return false
	}

	highestPriority := sources[0].Priority
	for _, source := range sources[1:] {
		if source.Priority > highestPriority {
			highestPriority = source.Priority
		}
	}
	for _, source := range sources {
		if source.Priority == highestPriority && source.Security {
			return true
		}
	}

	return false
}

func (client *Client) indexMetadata(ctx context.Context, targets []IndexTarget) (packageinfo.Metadata, error) {
	if len(targets) == 0 {
		return packageinfo.Metadata{}, errors.New("no enabled APT binary package indexes")
	}

	var oldest time.Time
	seen := make(map[string]struct{}, len(targets))
	for targetIndex, target := range targets {
		if err := ctx.Err(); err != nil {
			return packageinfo.Metadata{}, err
		}
		if _, duplicate := seen[target.Filename]; duplicate {
			continue
		}
		seen[target.Filename] = struct{}{}

		info, err := client.stat(target.Filename)
		if err != nil {
			return packageinfo.Metadata{}, &indexStatError{index: targetIndex + 1, err: err}
		}
		if info == nil {
			return packageinfo.Metadata{}, fmt.Errorf("APT package index %d returned no file metadata", targetIndex+1)
		}
		if !info.Mode().IsRegular() {
			return packageinfo.Metadata{}, fmt.Errorf("APT package index %d is not a regular file", targetIndex+1)
		}
		modified := info.ModTime().UTC()
		if modified.IsZero() {
			return packageinfo.Metadata{}, fmt.Errorf("APT package index %d has no modification time", targetIndex+1)
		}
		if oldest.IsZero() || modified.Before(oldest) {
			oldest = modified
		}
	}
	if oldest.IsZero() {
		return packageinfo.Metadata{}, errors.New("no unique APT package indexes participated")
	}

	now := client.now().UTC()
	age := int64(0)
	if now.After(oldest) {
		age = int64(now.Sub(oldest) / time.Second)
	}

	return packageinfo.Metadata{RefreshedAt: &oldest, AgeSeconds: &age}, nil
}

func (client *Client) run(
	ctx context.Context,
	operation string,
	path string,
	args []string,
	acceptedExitCodes []int,
) (command.Result, error) {
	result, err := client.runner.Run(ctx, command.Request{
		Name:              path,
		Args:              args,
		AcceptedExitCodes: acceptedExitCodes,
		Env: map[string]string{
			"LC_ALL": "C",
			"LANG":   "C",
		},
	})
	if err != nil {
		return result, &CommandError{
			operation:  operation,
			exitStatus: result.ExitCode,
			err:        err,
		}
	}

	return result, nil
}

type indexStatError struct {
	index int
	err   error
}

func (err *indexStatError) Error() string {
	return fmt.Sprintf("failed to stat APT package index %d", err.index)
}

func (err *indexStatError) Unwrap() error {
	return err.err
}
