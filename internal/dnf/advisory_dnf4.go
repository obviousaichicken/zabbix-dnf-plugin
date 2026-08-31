package dnf

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	errInvalidDNF4AdvisoryList = errors.New("invalid DNF4 advisory list")
	errInvalidDNF4AdvisoryInfo = errors.New("invalid DNF4 advisory info")
)

// ParseDNF4AdvisoryList parses the compact, applicable updateinfo list output.
func ParseDNF4AdvisoryList(data []byte) ([]Advisory, error) {
	byID := make(map[string]*Advisory)
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 {
			return nil, fmt.Errorf("%w: %q", errInvalidDNF4AdvisoryList, line)
		}
		id, classification, rawNEVRA := fields[0], fields[1], fields[2]
		if err := validateAdvisoryID(id); err != nil {
			return nil, fmt.Errorf("%w: %v", errInvalidDNF4AdvisoryList, err)
		}
		if !strings.HasSuffix(classification, "/Sec.") {
			return nil, fmt.Errorf("%w: unsupported classification %q", errInvalidDNF4AdvisoryList, classification)
		}
		severity := ParseAdvisorySeverity(strings.TrimSuffix(classification, "/Sec."))
		nevra, err := ParseNEVRA(rawNEVRA)
		if err != nil {
			return nil, fmt.Errorf("%w: advisory %q package: %v", errInvalidDNF4AdvisoryList, id, err)
		}

		advisory, exists := byID[id]
		if !exists {
			advisory = &Advisory{
				ID:              id,
				Type:            "security",
				Severity:        severity,
				CVEIDs:          make([]string, 0),
				References:      make([]AdvisoryReference, 0),
				AffectedUpdates: make([]NEVRA, 0),
			}
			byID[id] = advisory
		} else if advisory.Severity != severity {
			return nil, fmt.Errorf("%w: advisory %q has conflicting severities", errInvalidDNF4AdvisoryList, id)
		}

		duplicate := false
		for index, existing := range advisory.AffectedUpdates {
			if existing.matchKey() == nevra.matchKey() {
				duplicate = true
				if nevra.String() < existing.String() {
					advisory.AffectedUpdates[index] = nevra
				}
				break
			}
		}
		if !duplicate {
			advisory.AffectedUpdates = append(advisory.AffectedUpdates, nevra)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: read output: %v", errInvalidDNF4AdvisoryList, err)
	}

	advisories := make([]Advisory, 0, len(byID))
	for _, advisory := range byID {
		sort.Slice(advisory.AffectedUpdates, func(left, right int) bool {
			return advisory.AffectedUpdates[left].String() < advisory.AffectedUpdates[right].String()
		})
		advisories = append(advisories, *advisory)
	}
	sort.Slice(advisories, func(left, right int) bool {
		return advisories[left].ID < advisories[right].ID
	})

	return advisories, nil
}

type dnf4InfoRecord struct {
	advisory Advisory
	typeSeen bool
}

// ParseDNF4AdvisoryInfo parses the captured bulk detail format. The DNF4
// collector intentionally does not execute this command because it failed the
// cross-version timing gate; this parser keeps the vendor format contract
// explicit and fuzzable without adding a subprocess.
func ParseDNF4AdvisoryInfo(data []byte) ([]Advisory, error) {
	records := make(map[string]Advisory)
	var current *dnf4InfoRecord
	pendingTitle := ""
	continuation := ""

	finish := func() error {
		if current == nil {
			return nil
		}
		advisory := current.advisory
		if !current.typeSeen {
			return fmt.Errorf("%w: advisory %q has no type", errInvalidDNF4AdvisoryInfo, advisory.ID)
		}
		sort.Strings(advisory.CVEIDs)
		advisory.CVEIDs = slices.Compact(advisory.CVEIDs)
		if existing, found := records[advisory.ID]; found {
			if !sameDNF4Info(existing, advisory) {
				return fmt.Errorf("%w: advisory %q has conflicting details", errInvalidDNF4AdvisoryInfo, advisory.ID)
			}
		} else {
			records[advisory.ID] = advisory
		}
		current = nil
		continuation = ""

		return nil
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Trim(line, "=") == "" {
			continue
		}

		name, value, hasSeparator := strings.Cut(line, ":")
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if !hasSeparator {
			continue
		}

		switch name {
		case "Update ID":
			if err := finish(); err != nil {
				return nil, err
			}
			if err := validateAdvisoryID(value); err != nil {
				return nil, fmt.Errorf("%w: %v", errInvalidDNF4AdvisoryInfo, err)
			}
			current = &dnf4InfoRecord{advisory: Advisory{
				ID:              value,
				Type:            "security",
				Title:           pendingTitle,
				CVEIDs:          make([]string, 0),
				References:      make([]AdvisoryReference, 0),
				AffectedUpdates: make([]NEVRA, 0),
			}}
			pendingTitle = ""
			continuation = ""
		case "Type":
			if current == nil {
				continue
			}
			if !strings.EqualFold(value, "security") {
				return nil, fmt.Errorf("%w: advisory %q has type %q", errInvalidDNF4AdvisoryInfo, current.advisory.ID, value)
			}
			current.typeSeen = true
			continuation = ""
		case "Updated":
			if current == nil {
				continue
			}
			if value == "" {
				current.advisory.UpdatedAt = nil
				continuation = ""
				continue
			}
			updated, err := time.ParseInLocation("2006-01-02 15:04:05", value, time.UTC)
			if err != nil {
				return nil, fmt.Errorf("%w: advisory %q updated timestamp: %v", errInvalidDNF4AdvisoryInfo, current.advisory.ID, err)
			}
			updated = updated.UTC()
			current.advisory.UpdatedAt = &updated
			continuation = ""
		case "CVEs":
			if current == nil {
				continue
			}
			current.advisory.CVEIDs = append(current.advisory.CVEIDs, extractCVEIDs(value)...)
			continuation = "cves"
		case "Severity":
			if current == nil {
				continue
			}
			current.advisory.Severity = ParseAdvisorySeverity(value)
			continuation = ""
		case "":
			if current != nil && continuation == "cves" {
				current.advisory.CVEIDs = append(current.advisory.CVEIDs, extractCVEIDs(value)...)
			}
		default:
			if isDNF4TitlePrefix(name) {
				pendingTitle = value
			}
			if name == "Description" {
				continuation = "description"
			} else {
				continuation = ""
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("%w: read output: %v", errInvalidDNF4AdvisoryInfo, err)
	}
	if err := finish(); err != nil {
		return nil, err
	}

	advisories := make([]Advisory, 0, len(records))
	for _, advisory := range records {
		advisories = append(advisories, advisory)
	}
	sort.Slice(advisories, func(left, right int) bool {
		return advisories[left].ID < advisories[right].ID
	})

	return advisories, nil
}

func isDNF4TitlePrefix(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "important", "moderate", "low", "none", "unknown":
		return true
	default:
		return false
	}
}

func sameDNF4Info(left, right Advisory) bool {
	if left.ID != right.ID || left.Type != right.Type || left.Severity != right.Severity ||
		left.Title != right.Title || !slices.Equal(left.CVEIDs, right.CVEIDs) {
		return false
	}
	if left.UpdatedAt == nil || right.UpdatedAt == nil {
		return left.UpdatedAt == nil && right.UpdatedAt == nil
	}

	return left.UpdatedAt.Equal(*right.UpdatedAt)
}

func (c *Client) securityAdvisoriesDNF4(ctx context.Context) (AdvisoryData, error) {
	result, err := c.run(
		ctx,
		"-q",
		"--setopt=*.skip_if_unavailable=False",
		"updateinfo",
		"list",
		"--updates",
		"--security",
	)
	if err != nil {
		return AdvisoryData{}, fmt.Errorf("list DNF4 security advisories: %w", err)
	}

	advisories, err := ParseDNF4AdvisoryList(result.Stdout)
	if err != nil {
		return AdvisoryData{}, fmt.Errorf("parse DNF4 security advisories: %w", err)
	}

	return AdvisoryData{
		CollectedAt: time.Now().UTC(),
		Capabilities: AdvisoryCapabilities{
			DetailsComplete:    false,
			CVEsComplete:       false,
			IssueDatesComplete: false,
		},
		Advisories: advisories,
	}, nil
}
