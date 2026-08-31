package dnf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	errInvalidDNF5AdvisoryList = errors.New("invalid DNF5 advisory list")
	errInvalidDNF5AdvisoryInfo = errors.New("invalid DNF5 advisory info")
	errInvalidDNF5AdvisoryData = errors.New("invalid DNF5 advisory data")
)

type dnf5ListEntry struct {
	Name      string          `json:"name"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"`
	NEVRA     string          `json:"nevra"`
	BuildTime json.RawMessage `json:"buildtime"`
}

type dnf5RawReference struct {
	Title string `json:"Title"`
	ID    string `json:"Id"`
	Type  string `json:"Type"`
	URL   string `json:"Url"`
}

type dnf5RawCollections struct {
	Packages []string `json:"packages"`
}

type dnf5InfoEntry struct {
	Name        string             `json:"Name"`
	Title       string             `json:"Title"`
	Severity    string             `json:"Severity"`
	Type        string             `json:"Type"`
	Issued      json.RawMessage    `json:"Issued"`
	Updated     json.RawMessage    `json:"Updated"`
	Description string             `json:"Description"`
	References  []dnf5RawReference `json:"references"`
	Collections dnf5RawCollections `json:"collections"`
}

// parseDNF5AdvisoryList parses the applicable advisory/package relationships.
// The list command is the only authority for which package builds affect the
// host; build timestamps are validated but are not promoted to vendor issue
// dates.
func parseDNF5AdvisoryList(data []byte, version DNFVersion) ([]Advisory, error) {
	if err := validateDNF5AdvisoryVersion(version); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidDNF5AdvisoryList, err)
	}
	if firstJSONByte(data) != '[' {
		return nil, fmt.Errorf("%w: top-level value is not an array", errInvalidDNF5AdvisoryList)
	}

	var entries []dnf5ListEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, fmt.Errorf("%w: decode JSON: %v", errInvalidDNF5AdvisoryList, err)
	}

	byID := make(map[string]*Advisory)
	for index, entry := range entries {
		if err := validateAdvisoryID(entry.Name); err != nil {
			return nil, fmt.Errorf("%w: record %d: %v", errInvalidDNF5AdvisoryList, index, err)
		}
		if !strings.EqualFold(strings.TrimSpace(entry.Type), "security") {
			return nil, fmt.Errorf(
				"%w: advisory %q has type %q",
				errInvalidDNF5AdvisoryList,
				entry.Name,
				entry.Type,
			)
		}
		if _, err := parseDNF5Timestamp(entry.BuildTime, version); err != nil {
			return nil, fmt.Errorf(
				"%w: advisory %q build timestamp: %v",
				errInvalidDNF5AdvisoryList,
				entry.Name,
				err,
			)
		}

		nevra, err := ParseNEVRA(entry.NEVRA)
		if err != nil {
			return nil, fmt.Errorf(
				"%w: advisory %q package: %v",
				errInvalidDNF5AdvisoryList,
				entry.Name,
				err,
			)
		}
		severity := ParseAdvisorySeverity(entry.Severity)
		advisory, found := byID[entry.Name]
		if !found {
			advisory = &Advisory{
				ID:              entry.Name,
				Type:            "security",
				Severity:        severity,
				CVEIDs:          make([]string, 0),
				References:      make([]AdvisoryReference, 0),
				AffectedUpdates: make([]NEVRA, 0),
			}
			byID[entry.Name] = advisory
		} else if advisory.Severity != severity {
			return nil, fmt.Errorf(
				"%w: advisory %q has conflicting severities",
				errInvalidDNF5AdvisoryList,
				entry.Name,
			)
		}
		advisory.AffectedUpdates = appendUniqueNEVRA(advisory.AffectedUpdates, nevra)
	}

	advisories := make([]Advisory, 0, len(byID))
	for _, advisory := range byID {
		sortNEVRAs(advisory.AffectedUpdates)
		advisories = append(advisories, *advisory)
	}
	sort.Slice(advisories, func(left, right int) bool {
		return advisories[left].ID < advisories[right].ID
	})

	return advisories, nil
}

func parseDNF5AdvisoryInfo(data []byte, version DNFVersion) (map[string]Advisory, error) {
	if err := validateDNF5AdvisoryVersion(version); err != nil {
		return nil, fmt.Errorf("%w: %v", errInvalidDNF5AdvisoryInfo, err)
	}

	entries, err := decodeDNF5InfoEntries(data, version)
	if err != nil {
		return nil, err
	}

	byID := make(map[string]Advisory, len(entries))
	for index, entry := range entries {
		advisory, parseErr := parseDNF5InfoEntry(entry, version)
		if parseErr != nil {
			return nil, fmt.Errorf("%w: record %d: %v", errInvalidDNF5AdvisoryInfo, index, parseErr)
		}
		if existing, found := byID[advisory.ID]; found {
			if !sameDNF5Info(existing, advisory) {
				return nil, fmt.Errorf(
					"%w: advisory %q has conflicting details",
					errInvalidDNF5AdvisoryInfo,
					advisory.ID,
				)
			}
			continue
		}
		byID[advisory.ID] = advisory
	}

	return byID, nil
}

func decodeDNF5InfoEntries(data []byte, version DNFVersion) ([]dnf5InfoEntry, error) {
	if version.AtLeast(5, 3) {
		if firstJSONByte(data) != '[' {
			return nil, fmt.Errorf("%w: top-level value is not an array", errInvalidDNF5AdvisoryInfo)
		}
		var entries []dnf5InfoEntry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, fmt.Errorf("%w: decode JSON: %v", errInvalidDNF5AdvisoryInfo, err)
		}

		return entries, nil
	}

	if firstJSONByte(data) != '{' {
		return nil, fmt.Errorf("%w: top-level value is not an object", errInvalidDNF5AdvisoryInfo)
	}
	var keyed map[string]json.RawMessage
	if err := json.Unmarshal(data, &keyed); err != nil {
		return nil, fmt.Errorf("%w: decode JSON: %v", errInvalidDNF5AdvisoryInfo, err)
	}

	keys := make([]string, 0, len(keyed))
	for key := range keyed {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	entries := make([]dnf5InfoEntry, 0, len(keys))
	for _, key := range keys {
		if err := validateAdvisoryID(key); err != nil {
			return nil, fmt.Errorf("%w: object key: %v", errInvalidDNF5AdvisoryInfo, err)
		}
		var entry dnf5InfoEntry
		if err := json.Unmarshal(keyed[key], &entry); err != nil {
			return nil, fmt.Errorf(
				"%w: advisory %q: decode record: %v",
				errInvalidDNF5AdvisoryInfo,
				key,
				err,
			)
		}
		if entry.Name == "" {
			return nil, fmt.Errorf("%w: advisory %q has no Name", errInvalidDNF5AdvisoryInfo, key)
		}
		if entry.Name != key {
			return nil, fmt.Errorf(
				"%w: object key %q conflicts with Name %q",
				errInvalidDNF5AdvisoryInfo,
				key,
				entry.Name,
			)
		}
		entries = append(entries, entry)
	}

	return entries, nil
}

func parseDNF5InfoEntry(entry dnf5InfoEntry, version DNFVersion) (Advisory, error) {
	if err := validateAdvisoryID(entry.Name); err != nil {
		return Advisory{}, err
	}
	if !strings.EqualFold(strings.TrimSpace(entry.Type), "security") {
		return Advisory{}, fmt.Errorf("advisory %q has type %q", entry.Name, entry.Type)
	}

	issuedAt, err := parseDNF5Timestamp(entry.Issued, version)
	if err != nil {
		return Advisory{}, fmt.Errorf("advisory %q issued timestamp: %w", entry.Name, err)
	}
	updatedAt, err := parseDNF5Timestamp(entry.Updated, version)
	if err != nil {
		return Advisory{}, fmt.Errorf("advisory %q updated timestamp: %w", entry.Name, err)
	}

	packages := make([]NEVRA, 0, len(entry.Collections.Packages))
	for _, value := range entry.Collections.Packages {
		nevra, parseErr := ParseNEVRA(value)
		if parseErr != nil {
			return Advisory{}, fmt.Errorf("advisory %q package: %w", entry.Name, parseErr)
		}
		packages = appendUniqueNEVRA(packages, nevra)
	}
	sortNEVRAs(packages)

	references := make([]AdvisoryReference, 0, len(entry.References))
	for _, reference := range entry.References {
		normalized := AdvisoryReference{
			Type:  strings.ToLower(strings.TrimSpace(reference.Type)),
			ID:    strings.TrimSpace(reference.ID),
			Title: strings.TrimSpace(reference.Title),
			URL:   strings.TrimSpace(reference.URL),
		}
		if normalized == (AdvisoryReference{}) {
			continue
		}
		references = append(references, normalized)
	}
	sortReferences(references)
	references = slices.Compact(references)

	cveIDs := extractDNF5CVEIDs(entry.Description, references)

	return Advisory{
		ID:              entry.Name,
		Type:            "security",
		Severity:        ParseAdvisorySeverity(entry.Severity),
		Title:           strings.TrimSpace(entry.Title),
		IssuedAt:        issuedAt,
		UpdatedAt:       updatedAt,
		CVEIDs:          cveIDs,
		References:      references,
		AffectedUpdates: packages,
	}, nil
}

func reconcileDNF5Advisories(
	applicable []Advisory,
	details map[string]Advisory,
) ([]Advisory, AdvisoryCapabilities, error) {
	capabilities := AdvisoryCapabilities{
		DetailsComplete:    true,
		CVEsComplete:       true,
		IssueDatesComplete: true,
	}
	result := make([]Advisory, len(applicable))
	for index, listed := range applicable {
		detail, found := details[listed.ID]
		if !found {
			capabilities.DetailsComplete = false
			capabilities.CVEsComplete = false
			capabilities.IssueDatesComplete = false
			result[index] = listed
			continue
		}
		if listed.Type != detail.Type || listed.Severity != detail.Severity {
			return nil, AdvisoryCapabilities{}, fmt.Errorf(
				"%w: advisory %q list and detail classifications conflict",
				errInvalidDNF5AdvisoryData,
				listed.ID,
			)
		}

		listed.Title = detail.Title
		listed.IssuedAt = detail.IssuedAt
		listed.UpdatedAt = detail.UpdatedAt
		listed.CVEIDs = append([]string(nil), detail.CVEIDs...)
		listed.References = append([]AdvisoryReference(nil), detail.References...)
		if listed.CVEIDs == nil {
			listed.CVEIDs = make([]string, 0)
		}
		if listed.References == nil {
			listed.References = make([]AdvisoryReference, 0)
		}

		if listed.Title == "" || !containsAllNEVRAs(detail.AffectedUpdates, listed.AffectedUpdates) {
			capabilities.DetailsComplete = false
		}
		if listed.IssuedAt == nil {
			capabilities.IssueDatesComplete = false
		}
		result[index] = listed
	}

	return result, capabilities, nil
}

func parseDNF5Advisories(
	listData []byte,
	infoData []byte,
	version DNFVersion,
) ([]Advisory, AdvisoryCapabilities, error) {
	applicable, err := parseDNF5AdvisoryList(listData, version)
	if err != nil {
		return nil, AdvisoryCapabilities{}, err
	}
	details, err := parseDNF5AdvisoryInfo(infoData, version)
	if err != nil {
		return nil, AdvisoryCapabilities{}, err
	}

	return reconcileDNF5Advisories(applicable, details)
}

func parseDNF5Timestamp(raw json.RawMessage, version DNFVersion) (*time.Time, error) {
	value := bytes.TrimSpace(raw)
	if len(value) == 0 || bytes.Equal(value, []byte("null")) {
		return nil, nil
	}

	var timestamp time.Time
	if version.AtLeast(5, 3) {
		var seconds int64
		if err := json.Unmarshal(value, &seconds); err != nil {
			return nil, fmt.Errorf("expected integer Unix timestamp: %w", err)
		}
		timestamp = time.Unix(seconds, 0).UTC()
	} else {
		var text string
		if err := json.Unmarshal(value, &text); err != nil {
			return nil, fmt.Errorf("expected string timestamp: %w", err)
		}
		if text == "" {
			return nil, nil
		}
		parsed, err := time.ParseInLocation("2006-01-02 15:04:05", text, time.UTC)
		if err != nil {
			return nil, err
		}
		timestamp = parsed.UTC()
	}
	if timestamp.Year() < 1 || timestamp.Year() > 9999 {
		return nil, fmt.Errorf("timestamp year %d is outside RFC 3339", timestamp.Year())
	}

	return &timestamp, nil
}

func extractDNF5CVEIDs(description string, references []AdvisoryReference) []string {
	ids := make([]string, 0)
	for _, reference := range references {
		if strings.EqualFold(reference.Type, "cve") {
			ids = append(ids, extractCVEIDs(reference.ID)...)
			ids = append(ids, extractCVEIDs(reference.Title)...)
		}
	}
	for _, reference := range references {
		if !strings.EqualFold(reference.Type, "cve") {
			ids = append(ids, extractCVEIDs(reference.ID)...)
			ids = append(ids, extractCVEIDs(reference.Title)...)
		}
	}
	ids = append(ids, extractCVEIDs(description)...)
	sort.Strings(ids)

	return slices.Compact(ids)
}

func appendUniqueNEVRA(values []NEVRA, candidate NEVRA) []NEVRA {
	for index, existing := range values {
		if existing.matchKey() != candidate.matchKey() {
			continue
		}
		if candidate.String() < existing.String() {
			values[index] = candidate
		}

		return values
	}

	return append(values, candidate)
}

func sortNEVRAs(values []NEVRA) {
	sort.Slice(values, func(left, right int) bool {
		return values[left].String() < values[right].String()
	})
}

func sortReferences(values []AdvisoryReference) {
	sort.Slice(values, func(left, right int) bool {
		leftKey := values[left].Type + "\x00" + values[left].ID + "\x00" +
			values[left].Title + "\x00" + values[left].URL
		rightKey := values[right].Type + "\x00" + values[right].ID + "\x00" +
			values[right].Title + "\x00" + values[right].URL

		return leftKey < rightKey
	})
}

func containsAllNEVRAs(available, required []NEVRA) bool {
	keys := make(map[string]struct{}, len(available))
	for _, value := range available {
		keys[value.matchKey()] = struct{}{}
	}
	for _, value := range required {
		if _, found := keys[value.matchKey()]; !found {
			return false
		}
	}

	return true
}

func sameDNF5Info(left, right Advisory) bool {
	if left.ID != right.ID || left.Type != right.Type || left.Severity != right.Severity ||
		left.Title != right.Title || !slices.Equal(left.CVEIDs, right.CVEIDs) ||
		!slices.Equal(left.References, right.References) ||
		!slices.EqualFunc(left.AffectedUpdates, right.AffectedUpdates, func(a, b NEVRA) bool {
			return a.exactKey() == b.exactKey()
		}) {
		return false
	}
	if !sameOptionalTime(left.IssuedAt, right.IssuedAt) {
		return false
	}

	return sameOptionalTime(left.UpdatedAt, right.UpdatedAt)
}

func sameOptionalTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Equal(*right)
}

func firstJSONByte(data []byte) byte {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return 0
	}

	return trimmed[0]
}

func validateDNF5AdvisoryVersion(version DNFVersion) error {
	if !version.DNF5 || version.Major < 5 {
		return fmt.Errorf("DNF5 version is required, got %q", version.String())
	}

	return nil
}

func (c *Client) securityAdvisoriesDNF5(
	ctx context.Context,
	version DNFVersion,
) (AdvisoryData, error) {
	listResult, err := c.run(
		ctx,
		"-q",
		"--setopt=*.skip_if_unavailable=False",
		"advisory",
		"list",
		"--updates",
		"--security",
		"--json",
	)
	if err != nil {
		return AdvisoryData{}, fmt.Errorf("list DNF5 security advisories: %w", err)
	}

	infoResult, err := c.run(
		ctx,
		"-q",
		"--setopt=*.skip_if_unavailable=False",
		"advisory",
		"info",
		"--updates",
		"--security",
		"--json",
	)
	if err != nil {
		return AdvisoryData{}, fmt.Errorf("read DNF5 security advisory details: %w", err)
	}

	advisories, capabilities, err := parseDNF5Advisories(
		listResult.Stdout,
		infoResult.Stdout,
		version,
	)
	if err != nil {
		return AdvisoryData{}, fmt.Errorf("parse DNF5 security advisories: %w", err)
	}

	return AdvisoryData{
		CollectedAt:  time.Now().UTC(),
		Capabilities: capabilities,
		Advisories:   advisories,
	}, nil
}
