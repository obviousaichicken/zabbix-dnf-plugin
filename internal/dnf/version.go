package dnf

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const dnf5VersionPrefix = "dnf5 version "

// DNFVersion is the parsed command family and numeric version.
type DNFVersion struct {
	Major int
	Minor int
	DNF5  bool
	raw   string
}

// String returns the original normalized numeric version token.
func (v DNFVersion) String() string {
	return v.raw
}

// AtLeast reports whether the numeric version is at least major.minor.
func (v DNFVersion) AtLeast(major, minor int) bool {
	return v.Major > major || (v.Major == major && v.Minor >= minor)
}

// ParseDNFVersion parses the first DNF4 version token or the version token
// following the exact DNF5 prefix. Additional informational lines are ignored.
func ParseDNFVersion(data []byte) (DNFVersion, error) {
	output := strings.TrimSpace(string(data))
	if output == "" {
		return DNFVersion{}, errors.New("parse DNF version: output is empty")
	}

	if output == strings.TrimSpace(dnf5VersionPrefix) {
		return DNFVersion{}, errors.New("parse DNF5 version: version is missing")
	}
	dnf5 := strings.HasPrefix(output, dnf5VersionPrefix)
	var fields []string
	if dnf5 {
		fields = strings.Fields(strings.TrimPrefix(output, dnf5VersionPrefix))
		if len(fields) == 0 {
			return DNFVersion{}, errors.New("parse DNF5 version: version is missing")
		}
	} else {
		fields = strings.Fields(output)
	}

	token := fields[0]
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		if dnf5 {
			return DNFVersion{}, fmt.Errorf("parse DNF5 version %q: major and minor are required", token)
		}

		return DNFVersion{}, fmt.Errorf("parse DNF version %q: major and minor are required", token)
	}

	family := "DNF"
	if dnf5 {
		family = "DNF5"
	}
	majorValue, err := strconv.ParseUint(parts[0], 10, 32)
	if err != nil {
		return DNFVersion{}, fmt.Errorf("parse %s major version %q: %w", family, parts[0], err)
	}
	minorValue, err := strconv.ParseUint(parts[1], 10, 32)
	if err != nil {
		return DNFVersion{}, fmt.Errorf("parse %s minor version %q: %w", family, parts[1], err)
	}
	major := int(majorValue)
	minor := int(minorValue)

	for _, part := range parts[2:] {
		if part == "" {
			return DNFVersion{}, fmt.Errorf("parse DNF version %q: empty component", token)
		}
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return DNFVersion{}, fmt.Errorf("parse DNF version %q: component %q: %w", token, part, err)
		}
	}

	if dnf5 && major < 5 {
		return DNFVersion{}, fmt.Errorf("parse DNF5 version %q: major version is below 5", token)
	}

	return DNFVersion{Major: major, Minor: minor, DNF5: dnf5, raw: token}, nil
}

type commandCapabilities struct {
	Version     DNFVersion
	DNF5        bool
	HistoryJSON bool
}

func (c *Client) capabilities(ctx context.Context) (commandCapabilities, error) {
	result, err := c.run(ctx, "--version")
	if err != nil {
		return commandCapabilities{}, fmt.Errorf("read DNF version: %w", err)
	}

	output := strings.TrimSpace(string(result.Stdout))
	if !strings.HasPrefix(output, dnf5VersionPrefix) {
		// Preserve the legacy behavior: any non-DNF5 version output selects the
		// DNF4 command family. Parse it opportunistically for shared consumers.
		version, _ := ParseDNFVersion(result.Stdout)

		return commandCapabilities{Version: version}, nil
	}

	version, err := ParseDNFVersion(result.Stdout)
	if err != nil {
		return commandCapabilities{}, err
	}

	return commandCapabilities{
		Version:     version,
		DNF5:        true,
		HistoryJSON: version.AtLeast(5, 4),
	}, nil
}
