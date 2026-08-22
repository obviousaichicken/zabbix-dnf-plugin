package dnf

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// LastUpdate returns the latest completed package-upgrade transaction.
func (c *Client) LastUpdate(ctx context.Context) (*LastUpdate, error) {
	dnf5, historyJSON, err := c.historyCapabilities(ctx)
	if err != nil {
		return nil, err
	}
	if dnf5 {
		// Keep the DNF5 detail scan uncapped so an older upgrade is not silently
		// reported as absent. History is newest-first, upgrades are normally near
		// the front, and the caller's context bounds pathological scan time.
		if historyJSON {
			return c.lastUpdateDNF5JSON(ctx)
		}

		return c.lastUpdateDNF5Text(ctx)
	}

	return c.lastUpdateDNF4(ctx)
}

func (c *Client) historyCapabilities(ctx context.Context) (bool, bool, error) {
	result, err := c.run(ctx, "--version")
	if err != nil {
		return false, false, fmt.Errorf("read DNF version: %w", err)
	}

	const dnf5VersionPrefix = "dnf5 version "
	versionOutput := strings.TrimSpace(string(result.Stdout))
	if !strings.HasPrefix(versionOutput, dnf5VersionPrefix) {
		return false, false, nil
	}

	versionFields := strings.Fields(strings.TrimPrefix(versionOutput, dnf5VersionPrefix))
	if len(versionFields) == 0 {
		return false, false, errors.New("parse DNF5 version: version is missing")
	}
	version := versionFields[0]
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false, false, fmt.Errorf("parse DNF5 version %q", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return false, false, fmt.Errorf("parse DNF5 major version %q: %w", parts[0], err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return false, false, fmt.Errorf("parse DNF5 minor version %q: %w", parts[1], err)
	}

	return true, major > 5 || major == 5 && minor >= 4, nil
}
