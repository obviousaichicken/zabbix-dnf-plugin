package dnf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

type dnf5HistorySummary struct {
	ID int `json:"id"`
}

func (c *Client) lastUpdateDNF5JSON(ctx context.Context) (*LastUpdate, error) {
	result, err := c.run(ctx, "-q", "history", "list", "--json")
	if err != nil {
		return nil, fmt.Errorf("list DNF5 history: %w", err)
	}

	var transactions []dnf5HistorySummary
	if err := json.Unmarshal(result.Stdout, &transactions); err != nil {
		return nil, fmt.Errorf("parse DNF5 history list: %w", err)
	}

	for _, transaction := range transactions {
		if transaction.ID <= 0 {
			return nil, fmt.Errorf(
				"parse DNF5 history list: invalid transaction ID %d",
				transaction.ID,
			)
		}

		result, err := c.run(
			ctx,
			"-q",
			"history",
			"info",
			strconv.Itoa(transaction.ID),
			"--json",
		)
		if err != nil {
			return nil, fmt.Errorf("inspect DNF5 transaction %d: %w", transaction.ID, err)
		}

		lastUpdate, upgraded, err := parseDNF5HistoryInfo(result.Stdout)
		if err != nil {
			return nil, fmt.Errorf("parse DNF5 transaction %d: %w", transaction.ID, err)
		}
		if upgraded {
			return &lastUpdate, nil
		}
	}

	return nil, nil
}

func (c *Client) lastUpdateDNF5Text(ctx context.Context) (*LastUpdate, error) {
	result, err := c.run(ctx, "-q", "history", "list")
	if err != nil {
		return nil, fmt.Errorf("list DNF5 history: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(result.Stdout))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		id, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}

		result, err := c.run(ctx, "-q", "history", "info", strconv.Itoa(id))
		if err != nil {
			return nil, fmt.Errorf("inspect DNF5 transaction %d: %w", id, err)
		}

		lastUpdate, upgraded, err := parseTextHistoryInfo(result.Stdout)
		if err != nil {
			return nil, fmt.Errorf("parse DNF5 transaction %d: %w", id, err)
		}
		if upgraded {
			return &lastUpdate, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parse DNF5 history list: %w", err)
	}

	return nil, nil
}
