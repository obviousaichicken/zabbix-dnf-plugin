package dnf

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"strings"
)

const kernelQueryFormat = `%{NAME}|%{VERSION}-%{RELEASE}.%{ARCH}\n`

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
