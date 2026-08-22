package dnf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

const rebootPackageQueryFormat = `%{NAME}|%{INSTALLTIME}\n`

var (
	errRebootRunnerRequired = errors.New("reboot runner is required")
	errRPMPathRequired      = errors.New("rpm path is required")
	errUnamePathRequired    = errors.New("uname path is required")
)

// These core packages normally require a reboot after an update. Keeping the
// list locally avoids depending on optional DNF plugins for reboot detection.
var rebootSensitivePackages = map[string]struct{}{
	"dbus":           {},
	"dbus-broker":    {},
	"dbus-daemon":    {},
	"gnutls":         {},
	"glibc":          {},
	"linux-firmware": {},
	"microcode_ctl":  {},
	"openssl-libs":   {},
	"systemd":        {},
	"udev":           {},
}

// RebootCommands contains paths used for reboot detection.
type RebootCommands struct {
	RPM   string
	Uname string
}

// LookupRebootCommands resolves paths for reboot detection.
func LookupRebootCommands(
	lookup func(string) (string, error),
) (RebootCommands, error) {
	rpmPath, err := lookup("rpm")
	if err != nil {
		return RebootCommands{}, fmt.Errorf("find rpm: %w", err)
	}

	unamePath, err := lookup("uname")
	if err != nil {
		return RebootCommands{}, fmt.Errorf("find uname: %w", err)
	}

	return RebootCommands{
		RPM:   rpmPath,
		Uname: unamePath,
	}, nil
}

// RebootChecker combines package and kernel reboot checks.
type RebootChecker struct {
	runner   Runner
	commands RebootCommands
	bootTime func() (int64, error)
}

// NewRebootChecker creates a reboot checker.
func NewRebootChecker(
	runner Runner,
	commands RebootCommands,
) (*RebootChecker, error) {
	if runner == nil {
		return nil, errRebootRunnerRequired
	}
	if commands.RPM == "" {
		return nil, errRPMPathRequired
	}
	if commands.Uname == "" {
		return nil, errUnamePathRequired
	}

	return &RebootChecker{
		runner:   runner,
		commands: commands,
		bootTime: readBootTime,
	}, nil
}

// RebootPending reports whether a reboot is pending.
func (c *Client) RebootPending(ctx context.Context) (bool, error) {
	return c.rebootChecker.Pending(ctx)
}

// Pending reports whether a reboot is pending.
func (c *RebootChecker) Pending(ctx context.Context) (bool, error) {
	pending, err := c.rebootSensitivePackagesPending(ctx)
	if err != nil {
		return false, fmt.Errorf("check reboot-sensitive packages: %w", err)
	}
	if pending {
		return true, nil
	}

	return c.kernelPending(ctx)
}

func (c *RebootChecker) rebootSensitivePackagesPending(ctx context.Context) (bool, error) {
	bootTime, err := c.bootTime()
	if err != nil {
		return false, fmt.Errorf("read boot time: %w", err)
	}

	result, err := c.run(
		ctx,
		c.commands.RPM,
		[]string{"-qa", "--qf", rebootPackageQueryFormat},
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("query installed packages: %w", err)
	}

	return rebootSensitivePackageInstalled(result.Stdout, bootTime)
}

func readBootTime() (int64, error) {
	data, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0, fmt.Errorf("read /proc/stat: %w", err)
	}

	return parseBootTime(data)
}

func parseBootTime(data []byte) (int64, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[0] != "btime" {
			continue
		}

		bootTime, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse btime: %w", err)
		}

		return bootTime, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read /proc/stat: %w", err)
	}

	return 0, errors.New("btime not found in /proc/stat")
}

func rebootSensitivePackageInstalled(data []byte, bootTime int64) (bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "|", 2)
		if len(fields) != 2 {
			continue
		}
		if !isRebootSensitivePackage(fields[0]) {
			continue
		}

		installTime, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			return false, fmt.Errorf("parse install time for %q: %w", fields[0], err)
		}
		if installTime > bootTime {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("read installed packages: %w", err)
	}

	return false, nil
}

func isRebootSensitivePackage(name string) bool {
	if _, sensitive := rebootSensitivePackages[name]; sensitive {
		return true
	}

	return strings.Contains(name, "-firmware-") || strings.HasSuffix(name, "-firmware")
}

func (c *RebootChecker) run(
	ctx context.Context,
	path string,
	args []string,
	acceptedExitCodes []int,
) (command.Result, error) {
	return runCommand(ctx, c.runner, path, args, acceptedExitCodes)
}
