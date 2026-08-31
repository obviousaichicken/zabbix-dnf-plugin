package dnf

import (
	"context"
)

// SecurityAdvisories returns applicable security advisories independently of
// the legacy package snapshot. It is not registered as an Agent 2 item until
// the complete DNF4/DNF5 result contract is available.
func (c *Client) SecurityAdvisories(ctx context.Context) (AdvisoryData, error) {
	capabilities, err := c.capabilities(ctx)
	if err != nil {
		return AdvisoryData{}, err
	}
	if capabilities.DNF5 {
		return c.securityAdvisoriesDNF5(ctx, capabilities.Version)
	}

	return c.securityAdvisoriesDNF4(ctx)
}
