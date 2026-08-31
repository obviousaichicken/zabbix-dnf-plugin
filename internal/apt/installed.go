package apt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const (
	maxInstalledOutputBytes = 8 << 20
	maxInstalledLineBytes   = 1 << 20
)

// InstalledPackage is one package whose dpkg status is exactly installed.
type InstalledPackage struct {
	Name         string
	Architecture string
	Version      DebianVersion
}

// ParseInstalledPackages parses the pipe-delimited dpkg-query contract used by
// the APT collector. Residual package database entries are valid but omitted.
func ParseInstalledPackages(data []byte) ([]InstalledPackage, error) {
	if len(data) > maxInstalledOutputBytes {
		return nil, fmt.Errorf("installed-package output exceeds %d bytes", maxInstalledOutputBytes)
	}

	packages := make([]InstalledPackage, 0)
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), maxInstalledLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) != 4 {
			return nil, fmt.Errorf("malformed dpkg-query line %d: expected four fields", lineNumber)
		}
		for index := range fields {
			fields[index] = strings.TrimSpace(fields[index])
			if strings.ContainsAny(fields[index], "\x00\r\n") {
				return nil, fmt.Errorf("malformed dpkg-query line %d: invalid control character", lineNumber)
			}
		}

		name, err := parseBinaryPackage(fields[0], fields[1])
		if err != nil {
			return nil, fmt.Errorf("malformed dpkg-query line %d: %w", lineNumber, err)
		}
		if !knownPackageStatus(fields[3]) {
			return nil, fmt.Errorf("malformed dpkg-query line %d: unknown package status", lineNumber)
		}
		if fields[3] != "installed" {
			continue
		}

		version, err := ParseDebianVersion(fields[2])
		if err != nil {
			return nil, fmt.Errorf("malformed dpkg-query line %d: %w", lineNumber, err)
		}
		key := packageKey(name, fields[1])
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate installed package %s:%s", name, fields[1])
		}
		seen[key] = struct{}{}
		packages = append(packages, InstalledPackage{
			Name:         name,
			Architecture: fields[1],
			Version:      version,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("malformed dpkg-query output: line exceeds parser limit")
	}

	sort.Slice(packages, func(left, right int) bool {
		if packages[left].Name != packages[right].Name {
			return packages[left].Name < packages[right].Name
		}

		return packages[left].Architecture < packages[right].Architecture
	})

	return packages, nil
}

func parseBinaryPackage(binaryPackage, architecture string) (string, error) {
	if !validArchitecture(architecture) {
		return "", errors.New("invalid package architecture")
	}

	name := binaryPackage
	if separator := strings.LastIndexByte(binaryPackage, ':'); separator >= 0 {
		name = binaryPackage[:separator]
		if binaryPackage[separator+1:] != architecture {
			return "", errors.New("binary package architecture does not match Architecture")
		}
	}
	if !validPackageName(name) {
		return "", errors.New("invalid binary package name")
	}

	return name, nil
}

func validPackageName(name string) bool {
	if len(name) < 2 || !lowerAlphaNumeric(name[0]) {
		return false
	}
	for _, character := range []byte(name[1:]) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '+' || character == '-' || character == '.' {
			continue
		}

		return false
	}

	return true
}

func validArchitecture(architecture string) bool {
	if architecture == "" || !lowerAlphaNumeric(architecture[0]) {
		return false
	}
	for _, character := range []byte(architecture[1:]) {
		if character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			character == '-' {
			continue
		}

		return false
	}

	return true
}

func lowerAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func knownPackageStatus(status string) bool {
	switch status {
	case "not-installed", "config-files", "half-installed", "unpacked",
		"half-configured", "triggers-awaited", "triggers-pending", "installed":
		return true
	default:
		return false
	}
}

func packageKey(name, architecture string) string {
	return name + "\x00" + architecture
}
