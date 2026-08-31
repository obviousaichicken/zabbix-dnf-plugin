package dnf

import (
	"context"
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
	capabilities, err := c.capabilities(ctx)
	if err != nil {
		return false, false, err
	}

	return capabilities.DNF5, capabilities.HistoryJSON, nil
}
