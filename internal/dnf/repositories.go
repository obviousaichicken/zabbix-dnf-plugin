package dnf

import (
	"context"
	"fmt"
)

// Repositories returns the enabled DNF repositories.
func (c *Client) Repositories(ctx context.Context) ([]Repository, error) {
	result, err := c.run(
		ctx,
		"-q",
		"repolist",
	)
	if err != nil {
		return nil, fmt.Errorf("list repositories: %w", err)
	}

	repositories, err := ParseRepositories(result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("parse repositories: %w", err)
	}

	return repositories, nil
}
