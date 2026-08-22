package dnf

import (
	"context"
	"fmt"
	"strconv"
)

func (c *Client) lastUpdateDNF4(ctx context.Context) (*LastUpdate, error) {
	result, err := c.run(ctx, "-q", "history", "list")
	if err != nil {
		return nil, fmt.Errorf("list DNF history: %w", err)
	}

	transactions, err := parseDNF4HistoryList(result.Stdout)
	if err != nil {
		return nil, fmt.Errorf("parse DNF history list: %w", err)
	}
	for _, transaction := range transactions {
		if !transaction.hasUpgrade {
			continue
		}

		result, err := c.run(
			ctx,
			"-q",
			"history",
			"info",
			strconv.Itoa(transaction.id),
		)
		if err != nil {
			return nil, fmt.Errorf(
				"inspect DNF transaction %d: %w",
				transaction.id,
				err,
			)
		}

		lastUpdate, upgraded, err := parseTextHistoryInfo(result.Stdout)
		if err != nil {
			return nil, fmt.Errorf(
				"parse DNF transaction %d: %w",
				transaction.id,
				err,
			)
		}

		if upgraded {
			return &lastUpdate, nil
		}
	}

	return nil, nil
}
