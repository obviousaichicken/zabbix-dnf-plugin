package results

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
)

const (
	AdvisorySchemaVersion   = 1
	maxAdvisoryPayloadBytes = 8 << 20
)

var (
	errAdvisoryPayloadTooLarge = errors.New("advisory payload too large")
	advisoryCVEPattern         = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,}$`)
)

// AdvisoryPayload is the compact dnf.advisories.get response.
type AdvisoryPayload struct {
	SchemaVersion int                `json:"schema_version"` //nolint:tagliatelle // Public schema uses snake_case.
	Collection    AdvisoryCollection `json:"collection"`
	Metadata      AdvisoryMetadata   `json:"metadata"`
	Summary       AdvisorySummary    `json:"summary"`
	Advisories    []AdvisoryResult   `json:"advisories"`
}

// AdvisoryCollection records successful collection timing.
type AdvisoryCollection struct {
	Complete    bool      `json:"complete"`
	DurationMS  int64     `json:"duration_ms"`  //nolint:tagliatelle // Public schema uses snake_case.
	CollectedAt time.Time `json:"collected_at"` //nolint:tagliatelle // Public schema uses snake_case.
}

// AdvisoryMetadata records whether optional vendor detail is authoritative.
type AdvisoryMetadata struct {
	DetailsComplete    bool `json:"details_complete"`     //nolint:tagliatelle // Public schema uses snake_case.
	CVEsComplete       bool `json:"cves_complete"`        //nolint:tagliatelle // Public schema uses snake_case.
	IssueDatesComplete bool `json:"issue_dates_complete"` //nolint:tagliatelle // Public schema uses snake_case.
}

// AdvisorySummary contains deduplicated advisory and affected-package counts.
type AdvisorySummary struct {
	Advisories                 int                    `json:"advisories"`
	UniqueCVEs                 int                    `json:"unique_cves"`                   //nolint:tagliatelle // Public schema uses snake_case.
	AdvisoriesBySeverity       AdvisorySeverityCounts `json:"advisories_by_severity"`        //nolint:tagliatelle // Public schema uses snake_case.
	PackageUpdatesBySeverity   AdvisorySeverityCounts `json:"package_updates_by_severity"`   //nolint:tagliatelle // Public schema uses snake_case.
	OldestVendorTimestamp      *time.Time             `json:"oldest_vendor_timestamp"`       //nolint:tagliatelle // Public schema uses snake_case.
	OldestVendorAgeSeconds     *int64                 `json:"oldest_vendor_age_seconds"`     //nolint:tagliatelle // Public schema uses snake_case.
	OldestVendorTimestampBasis string                 `json:"oldest_vendor_timestamp_basis"` //nolint:tagliatelle // Public schema uses snake_case.
}

// AdvisorySeverityCounts is a complete severity partition.
type AdvisorySeverityCounts struct {
	Critical  int `json:"critical"`
	Important int `json:"important"`
	Moderate  int `json:"moderate"`
	Low       int `json:"low"`
	Unknown   int `json:"unknown"`
}

// AdvisoryResult is one deterministic compact advisory record.
type AdvisoryResult struct {
	ID                   string     `json:"id"`
	Type                 string     `json:"type"`
	Severity             string     `json:"severity"`
	Title                string     `json:"title"`
	IssuedAt             *time.Time `json:"issued_at"`              //nolint:tagliatelle // Public schema uses snake_case.
	UpdatedAt            *time.Time `json:"updated_at"`             //nolint:tagliatelle // Public schema uses snake_case.
	CVEIDs               []string   `json:"cve_ids"`                //nolint:tagliatelle // Public schema uses snake_case.
	AffectedUpdateNEVRAs []string   `json:"affected_update_nevras"` //nolint:tagliatelle // Public schema uses snake_case.
}

type advisoryAggregate struct {
	id         string
	typeName   string
	severity   dnf.AdvisorySeverity
	title      string
	issuedAt   *time.Time
	updatedAt  *time.Time
	cveIDs     map[string]struct{}
	references map[string]dnf.AdvisoryReference
	packages   map[string]dnf.NEVRA
}

// BuildAdvisories validates and aggregates one DNF advisory snapshot. Vendor
// age is calculated against the snapshot's collection timestamp so a payload
// remains internally consistent and deterministic.
//
//nolint:funlen,cyclop // Validation and aggregation form one trust boundary.
func BuildAdvisories(data dnf.AdvisoryData) (AdvisoryPayload, error) {
	collectedAt, err := normalizeAdvisoryTimestamp(&data.CollectedAt)
	if err != nil || collectedAt == nil {
		return AdvisoryPayload{}, fmt.Errorf("invalid advisory collection timestamp: %w", err)
	}

	byID := make(map[string]*advisoryAggregate, len(data.Advisories))
	for index, advisory := range data.Advisories {
		normalized, normalizeErr := normalizeAdvisory(advisory)
		if normalizeErr != nil {
			return AdvisoryPayload{}, fmt.Errorf("invalid advisory record %d: %w", index, normalizeErr)
		}

		aggregate, found := byID[normalized.id]
		if !found {
			byID[normalized.id] = normalized
			continue
		}
		if !sameAdvisoryCore(aggregate, normalized) {
			return AdvisoryPayload{}, fmt.Errorf("advisory %q has conflicting duplicate records", normalized.id)
		}
		mergeAdvisorySets(aggregate, normalized)
	}

	if data.Capabilities.DetailsComplete {
		for _, advisory := range byID {
			if advisory.title == "" {
				return AdvisoryPayload{}, fmt.Errorf(
					"advisory %q has no title while details are complete",
					advisory.id,
				)
			}
		}
	}
	if data.Capabilities.IssueDatesComplete {
		for _, advisory := range byID {
			if advisory.issuedAt == nil {
				return AdvisoryPayload{}, fmt.Errorf(
					"advisory %q has no issue date while issue dates are complete",
					advisory.id,
				)
			}
		}
	}

	payload := AdvisoryPayload{
		SchemaVersion: AdvisorySchemaVersion,
		Collection: AdvisoryCollection{
			Complete:    true,
			CollectedAt: *collectedAt,
		},
		Metadata: AdvisoryMetadata{
			DetailsComplete:    data.Capabilities.DetailsComplete,
			CVEsComplete:       data.Capabilities.CVEsComplete,
			IssueDatesComplete: data.Capabilities.IssueDatesComplete,
		},
		Summary: AdvisorySummary{
			OldestVendorTimestampBasis: "none",
		},
		Advisories: make([]AdvisoryResult, 0, len(byID)),
	}

	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	uniqueCVEs := make(map[string]struct{})
	packageSeverities := make(map[string]dnf.AdvisorySeverity)
	for _, id := range ids {
		advisory := byID[id]
		payload.Summary.AdvisoriesBySeverity.add(advisory.severity)

		cveIDs := make([]string, 0, len(advisory.cveIDs))
		for cveID := range advisory.cveIDs {
			cveIDs = append(cveIDs, cveID)
			uniqueCVEs[cveID] = struct{}{}
		}
		sort.Strings(cveIDs)

		packageNEVRAs := make([]string, 0, len(advisory.packages))
		for key, nevra := range advisory.packages {
			packageNEVRAs = append(packageNEVRAs, nevra.String())
			if current, found := packageSeverities[key]; !found || advisory.severity > current {
				packageSeverities[key] = advisory.severity
			}
		}
		sort.Strings(packageNEVRAs)

		payload.Advisories = append(payload.Advisories, AdvisoryResult{
			ID:                   advisory.id,
			Type:                 advisory.typeName,
			Severity:             advisory.severity.String(),
			Title:                advisory.title,
			IssuedAt:             cloneTime(advisory.issuedAt),
			UpdatedAt:            cloneTime(advisory.updatedAt),
			CVEIDs:               cveIDs,
			AffectedUpdateNEVRAs: packageNEVRAs,
		})
		updateOldestVendorTimestamp(&payload.Summary, advisory)
	}

	for _, severity := range packageSeverities {
		payload.Summary.PackageUpdatesBySeverity.add(severity)
	}
	payload.Summary.Advisories = len(payload.Advisories)
	payload.Summary.UniqueCVEs = len(uniqueCVEs)
	if payload.Summary.OldestVendorTimestamp != nil {
		age := vendorAgeSeconds(*collectedAt, *payload.Summary.OldestVendorTimestamp)
		payload.Summary.OldestVendorAgeSeconds = &age
	}

	if err := validateAdvisorySummary(payload, len(packageSeverities)); err != nil {
		return AdvisoryPayload{}, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return AdvisoryPayload{}, fmt.Errorf("marshal advisory payload for size validation: %w", err)
	}
	if len(encoded) > maxAdvisoryPayloadBytes {
		return AdvisoryPayload{}, fmt.Errorf(
			"%w: %d bytes, maximum is %d",
			errAdvisoryPayloadTooLarge,
			len(encoded),
			maxAdvisoryPayloadBytes,
		)
	}

	return payload, nil
}

func normalizeAdvisory(advisory dnf.Advisory) (*advisoryAggregate, error) {
	if err := validateResultAdvisoryID(advisory.ID); err != nil {
		return nil, err
	}
	if advisory.Type != "security" {
		return nil, fmt.Errorf("advisory %q has type %q", advisory.ID, advisory.Type)
	}
	if !advisory.Severity.Valid() {
		return nil, fmt.Errorf("advisory %q has invalid severity %d", advisory.ID, advisory.Severity)
	}
	if !utf8.ValidString(advisory.Title) || strings.IndexByte(advisory.Title, 0) >= 0 {
		return nil, fmt.Errorf("advisory %q title contains invalid text", advisory.ID)
	}
	title := strings.TrimSpace(advisory.Title)

	issuedAt, err := normalizeAdvisoryTimestamp(advisory.IssuedAt)
	if err != nil {
		return nil, fmt.Errorf("advisory %q issued timestamp: %w", advisory.ID, err)
	}
	updatedAt, err := normalizeAdvisoryTimestamp(advisory.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("advisory %q updated timestamp: %w", advisory.ID, err)
	}

	aggregate := &advisoryAggregate{
		id:         advisory.ID,
		typeName:   advisory.Type,
		severity:   advisory.Severity,
		title:      title,
		issuedAt:   issuedAt,
		updatedAt:  updatedAt,
		cveIDs:     make(map[string]struct{}, len(advisory.CVEIDs)),
		references: make(map[string]dnf.AdvisoryReference, len(advisory.References)),
		packages:   make(map[string]dnf.NEVRA, len(advisory.AffectedUpdates)),
	}
	for _, cveID := range advisory.CVEIDs {
		if !advisoryCVEPattern.MatchString(cveID) {
			return nil, fmt.Errorf("advisory %q has invalid CVE ID %q", advisory.ID, cveID)
		}
		aggregate.cveIDs[cveID] = struct{}{}
	}
	for _, reference := range advisory.References {
		if !utf8.ValidString(reference.Type) || !utf8.ValidString(reference.ID) ||
			!utf8.ValidString(reference.Title) || !utf8.ValidString(reference.URL) ||
			strings.IndexByte(reference.Type, 0) >= 0 || strings.IndexByte(reference.ID, 0) >= 0 ||
			strings.IndexByte(reference.Title, 0) >= 0 || strings.IndexByte(reference.URL, 0) >= 0 {
			return nil, fmt.Errorf("advisory %q has a reference containing invalid text", advisory.ID)
		}
		reference = dnf.AdvisoryReference{
			Type:  strings.ToLower(strings.TrimSpace(reference.Type)),
			ID:    strings.TrimSpace(reference.ID),
			Title: strings.TrimSpace(reference.Title),
			URL:   strings.TrimSpace(reference.URL),
		}
		if reference == (dnf.AdvisoryReference{}) {
			continue
		}
		key := reference.Type + "\x00" + reference.ID + "\x00" + reference.Title + "\x00" + reference.URL
		aggregate.references[key] = reference
	}
	for _, nevra := range advisory.AffectedUpdates {
		if !utf8.ValidString(nevra.String()) {
			return nil, fmt.Errorf("advisory %q has invalid package text", advisory.ID)
		}
		if err := nevra.Validate(); err != nil {
			return nil, fmt.Errorf("advisory %q has invalid package %q: %w", advisory.ID, nevra.String(), err)
		}
		key := advisoryNEVRAMatchKey(nevra)
		if existing, found := aggregate.packages[key]; !found || nevra.String() < existing.String() {
			aggregate.packages[key] = nevra
		}
	}

	return aggregate, nil
}

func validateResultAdvisoryID(id string) error {
	if id == "" || strings.TrimSpace(id) != id {
		return fmt.Errorf("invalid advisory ID %q", id)
	}
	for _, character := range id {
		if unicode.IsLetter(character) || unicode.IsDigit(character) ||
			strings.ContainsRune("-_.:+", character) {
			continue
		}

		return fmt.Errorf("invalid advisory ID %q", id)
	}

	return nil
}

func normalizeAdvisoryTimestamp(value *time.Time) (*time.Time, error) {
	if value == nil {
		return nil, nil
	}
	normalized := value.Round(0).UTC()
	if normalized.IsZero() || normalized.Year() < 1 || normalized.Year() > 9999 {
		return nil, errors.New("timestamp is zero or outside RFC 3339")
	}

	return &normalized, nil
}

func sameAdvisoryCore(left, right *advisoryAggregate) bool {
	return left.id == right.id && left.typeName == right.typeName &&
		left.severity == right.severity && left.title == right.title &&
		sameResultTime(left.issuedAt, right.issuedAt) &&
		sameResultTime(left.updatedAt, right.updatedAt)
}

func sameResultTime(left, right *time.Time) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}

	return left.Equal(*right)
}

func mergeAdvisorySets(destination, source *advisoryAggregate) {
	for cveID := range source.cveIDs {
		destination.cveIDs[cveID] = struct{}{}
	}
	for key, reference := range source.references {
		destination.references[key] = reference
	}
	for key, nevra := range source.packages {
		if existing, found := destination.packages[key]; !found || nevra.String() < existing.String() {
			destination.packages[key] = nevra
		}
	}
}

func advisoryNEVRAMatchKey(nevra dnf.NEVRA) string {
	epoch := nevra.Epoch
	if epoch == "" || epoch == "(none)" {
		epoch = "0"
	}

	return nevra.Name + "\x00" + epoch + "\x00" + nevra.Version + "\x00" +
		nevra.Release + "\x00" + nevra.Arch
}

func (counts *AdvisorySeverityCounts) add(severity dnf.AdvisorySeverity) {
	switch severity {
	case dnf.AdvisorySeverityCritical:
		counts.Critical++
	case dnf.AdvisorySeverityImportant:
		counts.Important++
	case dnf.AdvisorySeverityModerate:
		counts.Moderate++
	case dnf.AdvisorySeverityLow:
		counts.Low++
	case dnf.AdvisorySeverityUnknown:
		counts.Unknown++
	}
}

func (counts AdvisorySeverityCounts) total() int {
	return counts.Critical + counts.Important + counts.Moderate + counts.Low + counts.Unknown
}

func updateOldestVendorTimestamp(summary *AdvisorySummary, advisory *advisoryAggregate) {
	candidate := advisory.issuedAt
	basis := "issued"
	if candidate == nil {
		candidate = advisory.updatedAt
		basis = "updated"
	}
	if candidate == nil {
		return
	}
	if summary.OldestVendorTimestamp == nil || candidate.Before(*summary.OldestVendorTimestamp) ||
		(candidate.Equal(*summary.OldestVendorTimestamp) &&
			basis == "issued" && summary.OldestVendorTimestampBasis == "updated") {
		summary.OldestVendorTimestamp = cloneTime(candidate)
		summary.OldestVendorTimestampBasis = basis
	}
}

func vendorAgeSeconds(collectedAt, vendorTimestamp time.Time) int64 {
	if vendorTimestamp.After(collectedAt) {
		return 0
	}

	return collectedAt.Unix() - vendorTimestamp.Unix()
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value

	return &cloned
}

func validateAdvisorySummary(payload AdvisoryPayload, uniquePackages int) error {
	if payload.Summary.Advisories != len(payload.Advisories) ||
		payload.Summary.AdvisoriesBySeverity.total() != len(payload.Advisories) {
		return errors.New("advisory summary count invariant failed")
	}
	if payload.Summary.PackageUpdatesBySeverity.total() != uniquePackages {
		return errors.New("advisory package count invariant failed")
	}
	if !slices.IsSortedFunc(payload.Advisories, func(left, right AdvisoryResult) int {
		return strings.Compare(left.ID, right.ID)
	}) {
		return errors.New("advisory ordering invariant failed")
	}
	for _, advisory := range payload.Advisories {
		if !sort.StringsAreSorted(advisory.CVEIDs) || !sort.StringsAreSorted(advisory.AffectedUpdateNEVRAs) {
			return fmt.Errorf("advisory %q array ordering invariant failed", advisory.ID)
		}
	}
	if payload.Summary.OldestVendorTimestamp == nil {
		if payload.Summary.OldestVendorAgeSeconds != nil || payload.Summary.OldestVendorTimestampBasis != "none" {
			return errors.New("missing vendor timestamp summary is inconsistent")
		}
	} else if payload.Summary.OldestVendorAgeSeconds == nil ||
		(payload.Summary.OldestVendorTimestampBasis != "issued" &&
			payload.Summary.OldestVendorTimestampBasis != "updated") {
		return errors.New("vendor timestamp summary is inconsistent")
	}

	return nil
}
