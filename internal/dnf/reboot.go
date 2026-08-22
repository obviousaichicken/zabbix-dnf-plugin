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

const (
	kernelQueryFormat        = `%{NAME}|%{VERSION}-%{RELEASE}.%{ARCH}\n`
	rebootPackageQueryFormat = `%{NAME}|%{INSTALLTIME}\n`
)

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

// RebootCommands contains resolved paths used to determine whether a reboot is pending.
type RebootCommands struct {
	RPM   string
	Uname string
}

// LookupRebootCommands resolves the commands required for reboot detection.
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

// RebootChecker combines RPM install-time and kernel-version checks.
type RebootChecker struct {
	runner   Runner
	commands RebootCommands
	bootTime func() (int64, error)
}

// NewRebootChecker creates a reboot checker using resolved command paths.
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

// RebootPending reports whether installed package state recommends a reboot.
func (c *Client) RebootPending(ctx context.Context) (bool, error) {
	return c.rebootChecker.Pending(ctx)
}

// Pending reports whether installed package state recommends a reboot.
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

func (c *RebootChecker) kernelPending(ctx context.Context) (bool, error) {
	runningResult, err := c.run(ctx, c.commands.Uname, []string{"-r"}, nil)
	if err != nil {
		return false, fmt.Errorf("read running kernel: %w", err)
	}

	installedResult, err := c.run(
		ctx,
		c.commands.RPM,
		[]string{"-qa", "--qf", kernelQueryFormat, "kernel*"},
		nil,
	)
	if err != nil {
		return false, fmt.Errorf("query installed kernels: %w", err)
	}

	pending, err := newerKernelInstalled(
		installedResult.Stdout,
		strings.TrimSpace(string(runningResult.Stdout)),
	)
	if err != nil {
		return false, fmt.Errorf("compare installed kernels: %w", err)
	}

	return pending, nil
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
	result, err := c.runner.Run(ctx, command.Request{
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
			Command:    path + " " + strings.Join(args, " "),
			ExitStatus: result.ExitCode,
			Stderr:     strings.TrimSpace(string(result.Stderr)),
			Err:        err,
		}
	}

	return result, nil
}

type installedKernel struct {
	name    string
	release string
}

func newerKernelInstalled(data []byte, runningRelease string) (bool, error) {
	kernels, err := parseInstalledKernels(data)
	if err != nil {
		return false, err
	}

	runningPackages := make(map[string]struct{})
	for _, kernel := range kernels {
		if kernel.release == runningRelease {
			runningPackages[kernel.name] = struct{}{}
		}
	}
	if len(runningPackages) == 0 {
		return false, nil
	}

	for _, kernel := range kernels {
		if _, matchesFlavor := runningPackages[kernel.name]; !matchesFlavor {
			continue
		}
		if compareKernelRelease(kernel.release, runningRelease) > 0 {
			return true, nil
		}
	}

	return false, nil
}

func parseInstalledKernels(data []byte) ([]installedKernel, error) {
	kernels := make([]installedKernel, 0)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		fields := strings.SplitN(scanner.Text(), "|", 2)
		if len(fields) != 2 || !isKernelPackage(fields[0]) {
			continue
		}

		kernels = append(kernels, installedKernel{
			name:    fields[0],
			release: fields[1],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read installed kernels: %w", err)
	}

	return kernels, nil
}

func isKernelPackage(name string) bool {
	switch name {
	case "kernel", "kernel-core", "kernel-rt", "kernel-rt-core", "kernel-debug-core":
		return true
	default:
		return false
	}
}

// compareKernelRelease follows RPM's numeric/alphabetic segment ordering for
// the kernel release forms shipped by RHEL 8-10.
func compareKernelRelease(left, right string) int {
	for {
		leftPart, leftNumeric, leftRest := nextVersionPart(left)
		rightPart, rightNumeric, rightRest := nextVersionPart(right)

		switch {
		case leftPart == "" && rightPart == "":
			return 0
		case leftPart == "":
			return -1
		case rightPart == "":
			return 1
		case leftNumeric != rightNumeric:
			if leftNumeric {
				return 1
			}

			return -1
		}

		comparison := compareVersionPart(leftPart, rightPart, leftNumeric)
		if comparison != 0 {
			return comparison
		}

		left = leftRest
		right = rightRest
	}
}

func nextVersionPart(value string) (part string, numeric bool, rest string) {
	start := 0
	for start < len(value) && !isASCIILetter(value[start]) && !isASCIIDigit(value[start]) {
		start++
	}
	if start == len(value) {
		return "", false, ""
	}

	numeric = isASCIIDigit(value[start])
	end := start + 1
	for end < len(value) && isASCIIDigit(value[end]) == numeric &&
		(isASCIILetter(value[end]) || isASCIIDigit(value[end])) {
		end++
	}

	return value[start:end], numeric, value[end:]
}

func compareVersionPart(left, right string, numeric bool) int {
	if numeric {
		left = strings.TrimLeft(left, "0")
		right = strings.TrimLeft(right, "0")
		if len(left) != len(right) {
			if len(left) > len(right) {
				return 1
			}

			return -1
		}
	}

	return strings.Compare(left, right)
}

func isASCIIDigit(value byte) bool {
	return value >= '0' && value <= '9'
}

func isASCIILetter(value byte) bool {
	return value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z'
}
