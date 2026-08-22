package dnf

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

type dnf5HistoryTransaction struct {
	EndTime  int64  `json:"end_time"`
	Status   string `json:"status"`
	Packages []struct {
		Action string `json:"action"`
	} `json:"packages"`
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
