package dnf

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
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

type dnf5HistorySummary struct {
	ID int `json:"id"`
}

type dnf5HistoryTransaction struct {
	EndTime  int64  `json:"end_time"`
	Status   string `json:"status"`
	Packages []struct {
		Action string `json:"action"`
	} `json:"packages"`
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

func parseDNF5HistoryInfo(data []byte) (LastUpdate, bool, error) {
	var transactions []dnf5HistoryTransaction
	if err := json.Unmarshal(data, &transactions); err != nil {
		return LastUpdate{}, false, err
	}
	if len(transactions) != 1 {
		return LastUpdate{}, false, fmt.Errorf("expected one transaction, got %d", len(transactions))
	}

	transaction := transactions[0]
	for _, pkg := range transaction.Packages {
		if !strings.EqualFold(pkg.Action, "upgrade") {
			continue
		}
		if transaction.EndTime <= 0 && isUnfinishedHistoryStatus(transaction.Status) {
			// An unfinished transaction has no result yet. Continue searching for
			// the most recent completed upgrade.
			return LastUpdate{}, false, nil
		}
		if transaction.EndTime <= 0 {
			return LastUpdate{}, false, errors.New("invalid completed transaction end time")
		}

		result := LastUpdateResultFailed
		if strings.EqualFold(transaction.Status, "ok") {
			result = LastUpdateResultSuccess
		}

		return LastUpdate{
			Timestamp: time.Unix(transaction.EndTime, 0).UTC(),
			Result:    result,
		}, true, nil
	}

	return LastUpdate{}, false, nil
}

type historyTransaction struct {
	id         int
	hasUpgrade bool
}

func parseDNF4HistoryList(data []byte) ([]historyTransaction, error) {
	transactions := make([]historyTransaction, 0)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), "|")
		if len(fields) < 5 {
			continue
		}

		id, err := strconv.Atoi(strings.TrimSpace(fields[0]))
		if err != nil {
			continue
		}

		transactions = append(transactions, historyTransaction{
			id:         id,
			hasUpgrade: hasUpgradeLabel(fields[3]),
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read history list: %w", err)
	}

	return transactions, nil
}

func parseTextHistoryInfo(data []byte) (LastUpdate, bool, error) {
	var (
		endTimeText string
		status      string
		upgraded    bool
		inPackages  bool
	)

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lowerLine := strings.ToLower(line)

		switch {
		case strings.HasPrefix(lowerLine, "end time"):
			_, value, ok := strings.Cut(line, ":")
			if ok {
				endTimeText = strings.TrimSpace(value)
			}
		case strings.HasPrefix(lowerLine, "return-code"),
			strings.HasPrefix(lowerLine, "status"):
			_, value, ok := strings.Cut(line, ":")
			if ok {
				status = strings.TrimSpace(value)
			}
		case strings.HasPrefix(lowerLine, "packages altered"):
			inPackages = true
		default:
			fields := strings.Fields(line)
			if len(fields) > 0 && inPackages && hasUpgradeLabel(fields[0]) {
				upgraded = true
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return LastUpdate{}, false, fmt.Errorf("read history info: %w", err)
	}
	if !upgraded {
		return LastUpdate{}, false, nil
	}
	if endTimeText == "" && isUnfinishedHistoryStatus(status) {
		// DNF omits the end time while a transaction is unfinished.
		return LastUpdate{}, false, nil
	}
	if endTimeText == "" {
		return LastUpdate{}, false, errors.New("completed transaction has no end time")
	}

	timestamp, err := parseTextHistoryTime(endTimeText)
	if err != nil {
		return LastUpdate{}, false, fmt.Errorf("parse end time: %w", err)
	}

	return LastUpdate{
		Timestamp: timestamp,
		Result:    normalizeHistoryResult(status),
	}, true, nil
}

func isUnfinishedHistoryStatus(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "", "started", "running":
		return true
	default:
		return false
	}
}

func parseTextHistoryTime(value string) (time.Time, error) {
	value = strings.TrimSuffix(strings.TrimSpace(value), ".")
	if durationStart := strings.LastIndex(value, " ("); durationStart >= 0 && strings.HasSuffix(value, ")") {
		value = value[:durationStart]
	}

	for _, layout := range []string{
		time.RFC3339,
		"2006-01-02 15:04:05",
		time.ANSIC,
	} {
		parsed, err := time.ParseInLocation(layout, value, time.Local)
		if err == nil {
			return parsed.UTC(), nil
		}
	}

	return time.Time{}, fmt.Errorf("invalid timestamp %q", value)
}

func hasUpgradeLabel(label string) bool {
	for _, field := range strings.FieldsFunc(label, func(r rune) bool {
		return r == ',' || r == ' '
	}) {
		if strings.EqualFold(field, "upgrade") ||
			strings.EqualFold(field, "update") ||
			strings.EqualFold(field, "updated") ||
			strings.EqualFold(field, "u") {
			return true
		}
	}

	return false
}

func normalizeHistoryResult(status string) string {
	if strings.EqualFold(strings.TrimSpace(status), "success") ||
		strings.EqualFold(strings.TrimSpace(status), "ok") {
		return LastUpdateResultSuccess
	}

	return LastUpdateResultFailed
}
