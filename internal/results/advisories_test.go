package results_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/results"
)

func TestBuildAdvisoriesGolden(t *testing.T) {
	t.Parallel()

	payload, err := results.BuildAdvisories(goldenAdvisoryData())
	if err != nil {
		t.Fatalf("BuildAdvisories() error = %v", err)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	want, err := os.ReadFile("testdata/advisories.golden.json")
	if err != nil {
		t.Fatalf("read golden payload: %v; got: %s", err, data)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	if !bytes.Equal(data, want) {
		t.Fatalf("dnf.advisories.get payload changed\ngot:  %s\nwant: %s", data, want)
	}
	if len(data) >= 64<<10 {
		t.Fatalf("normal advisory payload is %d bytes, want below 64 KiB", len(data))
	}

	wantAdvisoryCounts := results.AdvisorySeverityCounts{Critical: 1, Important: 1, Moderate: 1}
	wantPackageCounts := results.AdvisorySeverityCounts{Critical: 2, Important: 1, Moderate: 1}
	if payload.Summary.Advisories != 3 || payload.Summary.UniqueCVEs != 3 ||
		payload.Summary.AdvisoriesBySeverity != wantAdvisoryCounts ||
		payload.Summary.PackageUpdatesBySeverity != wantPackageCounts {
		t.Fatalf("summary = %#v, want deduplicated advisory/CVE/package counts", payload.Summary)
	}
	if payload.Summary.OldestVendorTimestamp == nil ||
		payload.Summary.OldestVendorTimestamp.Format(time.RFC3339) != "2026-08-01T10:00:00Z" ||
		payload.Summary.OldestVendorAgeSeconds == nil || *payload.Summary.OldestVendorAgeSeconds != 2599200 ||
		payload.Summary.OldestVendorTimestampBasis != "issued" {
		t.Fatalf("oldest vendor summary = %#v, want issued timestamp and 2,599,200 seconds", payload.Summary)
	}
}

func TestBuildAdvisoriesDeduplicatesRelationships(t *testing.T) {
	t.Parallel()

	payload, err := results.BuildAdvisories(goldenAdvisoryData())
	if err != nil {
		t.Fatalf("BuildAdvisories() error = %v", err)
	}
	critical := payload.Advisories[0]
	if critical.ID != "FEDORA-2026-A" ||
		!slices.Equal(critical.CVEIDs, []string{"CVE-2026-12345", "CVE-2026-23456"}) ||
		!slices.Equal(critical.AffectedUpdateNEVRAs, []string{
			"example-0:2.0-1.x86_64",
			"shared-0:1.0-1.x86_64",
		}) {
		t.Fatalf("merged critical advisory = %#v", critical)
	}
}

func TestBuildAdvisoriesIncompleteDNF4Data(t *testing.T) {
	t.Parallel()

	collectedAt := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	local := time.FixedZone("vendor", 2*60*60)
	updatedAt := time.Date(2026, time.August, 20, 12, 0, 0, 0, local)
	data := dnf.AdvisoryData{
		CollectedAt: collectedAt,
		Advisories: []dnf.Advisory{{
			ID: "RLSA-2026:1", Type: "security", Severity: dnf.AdvisorySeverityUnknown,
			UpdatedAt: &updatedAt,
		}},
	}

	payload, err := results.BuildAdvisories(data)
	if err != nil {
		t.Fatalf("BuildAdvisories() error = %v", err)
	}
	if payload.Metadata != (results.AdvisoryMetadata{}) || payload.Advisories[0].Title != "" ||
		payload.Advisories[0].IssuedAt != nil || payload.Advisories[0].Severity != "unknown" ||
		payload.Advisories[0].CVEIDs == nil || payload.Advisories[0].AffectedUpdateNEVRAs == nil {
		t.Fatalf("incomplete payload = %#v, want explicit incomplete metadata and empty arrays", payload)
	}
	if payload.Advisories[0].UpdatedAt == nil ||
		payload.Advisories[0].UpdatedAt.Format(time.RFC3339) != "2026-08-20T10:00:00Z" ||
		payload.Summary.OldestVendorTimestampBasis != "updated" {
		t.Fatalf("updated timestamp normalization = %#v", payload)
	}
}

func TestBuildAdvisoriesFutureVendorTimestampHasZeroAge(t *testing.T) {
	t.Parallel()

	collectedAt := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	future := collectedAt.Add(time.Hour)
	payload, err := results.BuildAdvisories(dnf.AdvisoryData{
		CollectedAt: collectedAt,
		Advisories: []dnf.Advisory{{
			ID: "TEST-1", Type: "security", Severity: dnf.AdvisorySeverityLow, UpdatedAt: &future,
		}},
	})
	if err != nil {
		t.Fatalf("BuildAdvisories() error = %v", err)
	}
	if payload.Summary.OldestVendorAgeSeconds == nil || *payload.Summary.OldestVendorAgeSeconds != 0 {
		t.Fatalf("future vendor age = %v, want zero", payload.Summary.OldestVendorAgeSeconds)
	}
}

func TestBuildAdvisoriesEmptyArraysAndTimestampSummary(t *testing.T) {
	t.Parallel()

	payload, err := results.BuildAdvisories(dnf.AdvisoryData{
		CollectedAt: time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC),
		Capabilities: dnf.AdvisoryCapabilities{
			DetailsComplete: true, CVEsComplete: true, IssueDatesComplete: true,
		},
		Advisories: []dnf.Advisory{},
	})
	if err != nil {
		t.Fatalf("BuildAdvisories() error = %v", err)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if payload.Advisories == nil || !strings.Contains(string(encoded), `"advisories":[]`) ||
		payload.Summary.OldestVendorTimestamp != nil || payload.Summary.OldestVendorAgeSeconds != nil ||
		payload.Summary.OldestVendorTimestampBasis != "none" {
		t.Fatalf("empty payload = %s, want empty array and null/none timestamp summary", encoded)
	}
}

func TestBuildAdvisoriesIsDeterministic(t *testing.T) {
	t.Parallel()

	forward := goldenAdvisoryData()
	reversed := goldenAdvisoryData()
	slices.Reverse(reversed.Advisories)
	for index := range reversed.Advisories {
		slices.Reverse(reversed.Advisories[index].CVEIDs)
		slices.Reverse(reversed.Advisories[index].References)
		slices.Reverse(reversed.Advisories[index].AffectedUpdates)
	}

	left, err := results.BuildAdvisories(forward)
	if err != nil {
		t.Fatalf("BuildAdvisories(forward) error = %v", err)
	}
	right, err := results.BuildAdvisories(reversed)
	if err != nil {
		t.Fatalf("BuildAdvisories(reversed) error = %v", err)
	}
	leftJSON, _ := json.Marshal(left)
	rightJSON, _ := json.Marshal(right)
	if !bytes.Equal(leftJSON, rightJSON) {
		t.Fatalf("aggregation is order-dependent\nforward: %s\nreverse: %s", leftJSON, rightJSON)
	}
}

func TestBuildAdvisoriesRejectsInvalidData(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		mutate   func(*dnf.AdvisoryData)
		wantText string
	}{
		{name: "zero collection timestamp", mutate: func(data *dnf.AdvisoryData) { data.CollectedAt = time.Time{} }, wantText: "collection timestamp"},
		{name: "invalid ID", mutate: func(data *dnf.AdvisoryData) { data.Advisories[0].ID = "bad/id" }, wantText: "invalid advisory ID"},
		{name: "invalid type", mutate: func(data *dnf.AdvisoryData) { data.Advisories[0].Type = "bugfix" }, wantText: "has type"},
		{name: "invalid severity", mutate: func(data *dnf.AdvisoryData) { data.Advisories[0].Severity = dnf.AdvisorySeverity(255) }, wantText: "invalid severity"},
		{name: "title NUL", mutate: func(data *dnf.AdvisoryData) { data.Advisories[0].Title = "bad\x00title" }, wantText: "title contains invalid text"},
		{name: "zero issued timestamp", mutate: func(data *dnf.AdvisoryData) { zero := time.Time{}; data.Advisories[0].IssuedAt = &zero }, wantText: "issued timestamp"},
		{name: "malformed CVE", mutate: func(data *dnf.AdvisoryData) { data.Advisories[0].CVEIDs = []string{"cve-2026-1234"} }, wantText: "invalid CVE ID"},
		{name: "malformed package", mutate: func(data *dnf.AdvisoryData) {
			data.Advisories[0].AffectedUpdates = []dnf.NEVRA{{Name: "pkg", Version: "1", Release: "1"}}
		}, wantText: "invalid package"},
		{name: "reference NUL", mutate: func(data *dnf.AdvisoryData) {
			data.Advisories[0].References = []dnf.AdvisoryReference{{Type: "cve\x00"}}
		}, wantText: "reference containing invalid text"},
		{name: "conflicting duplicate", mutate: func(data *dnf.AdvisoryData) {
			duplicate := data.Advisories[0]
			duplicate.Title = "Different"
			data.Advisories = append(data.Advisories, duplicate)
		}, wantText: "conflicting duplicate"},
		{name: "complete details without title", mutate: func(data *dnf.AdvisoryData) { data.Advisories[0].Title = "" }, wantText: "no title while details are complete"},
		{name: "complete issue dates without issue date", mutate: func(data *dnf.AdvisoryData) { data.Advisories[0].IssuedAt = nil }, wantText: "no issue date while issue dates are complete"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			data := goldenAdvisoryData()
			test.mutate(&data)
			if _, err := results.BuildAdvisories(data); err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("BuildAdvisories() error = %v, want text %q", err, test.wantText)
			}
		})
	}
}

func TestBuildAdvisoriesThousandRecordStress(t *testing.T) {
	t.Parallel()

	const records = 1000
	collectedAt := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	data := dnf.AdvisoryData{
		CollectedAt: collectedAt,
		Capabilities: dnf.AdvisoryCapabilities{
			DetailsComplete: true, CVEsComplete: true, IssueDatesComplete: true,
		},
		Advisories: make([]dnf.Advisory, 0, records),
	}
	shared := dnf.NEVRA{Name: "shared", Version: "1", Release: "1", Arch: "x86_64"}
	for index := range records {
		severity := dnf.AdvisorySeverity(index % 5)
		issuedAt := collectedAt.Add(-time.Duration(index) * time.Hour)
		data.Advisories = append(data.Advisories, dnf.Advisory{
			ID:       fmt.Sprintf("ADV-2026:%04d", index),
			Type:     "security",
			Severity: severity,
			Title:    fmt.Sprintf("Advisory %d", index),
			IssuedAt: &issuedAt,
			CVEIDs:   []string{fmt.Sprintf("CVE-2026-%04d", index)},
			AffectedUpdates: []dnf.NEVRA{
				shared,
				{Name: fmt.Sprintf("pkg-%04d", index), Version: "1", Release: "1", Arch: "x86_64"},
			},
		})
	}

	payload, err := results.BuildAdvisories(data)
	if err != nil {
		t.Fatalf("BuildAdvisories() error = %v", err)
	}
	if payload.Summary.Advisories != records || payload.Summary.UniqueCVEs != records ||
		severityTotal(payload.Summary.PackageUpdatesBySeverity) != records+1 {
		t.Fatalf("stress summary = %#v, want %d advisories/CVEs and %d packages", payload.Summary, records, records+1)
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if len(encoded) >= 8<<20 {
		t.Fatalf("stress payload = %d bytes, want bounded below hard limit", len(encoded))
	}
}

func TestBuildAdvisoriesRejectsOversizePayload(t *testing.T) {
	t.Parallel()

	data := dnf.AdvisoryData{
		CollectedAt: time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC),
		Advisories: []dnf.Advisory{{
			ID:       "TEST-OVERSIZE",
			Type:     "security",
			Severity: dnf.AdvisorySeverityImportant,
			Title:    strings.Repeat("x", (8<<20)+1),
		}},
	}
	if _, err := results.BuildAdvisories(data); err == nil || !strings.Contains(err.Error(), "advisory payload too large") {
		t.Fatalf("BuildAdvisories() error = %v, want explicit advisory size error", err)
	}
}

func goldenAdvisoryData() dnf.AdvisoryData {
	collectedAt := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	issuedA := time.Date(2026, time.August, 1, 10, 0, 0, 0, time.UTC)
	issuedB := time.Date(2026, time.August, 15, 10, 0, 0, 0, time.UTC)
	issuedC := time.Date(2026, time.August, 20, 10, 0, 0, 0, time.UTC)
	example := dnf.NEVRA{Name: "example", Epoch: "0", Version: "2.0", Release: "1", Arch: "x86_64"}
	shared := dnf.NEVRA{Name: "shared", Version: "1.0", Release: "1", Arch: "x86_64"}
	reference := dnf.AdvisoryReference{Type: "cve", ID: "CVE-2026-12345", URL: "https://vendor.invalid/CVE-2026-12345"}

	return dnf.AdvisoryData{
		CollectedAt: collectedAt,
		Capabilities: dnf.AdvisoryCapabilities{
			DetailsComplete: true, CVEsComplete: true, IssueDatesComplete: true,
		},
		Advisories: []dnf.Advisory{
			{
				ID: "FEDORA-2026-B", Type: "security", Severity: dnf.AdvisorySeverityImportant,
				Title: "Important update", IssuedAt: &issuedB,
				CVEIDs: []string{"CVE-2026-34567", "CVE-2026-23456"},
				AffectedUpdates: []dnf.NEVRA{
					shared,
					{Name: "important-pkg", Version: "3", Release: "1", Arch: "noarch"},
				},
			},
			{
				ID: "FEDORA-2026-A", Type: "security", Severity: dnf.AdvisorySeverityCritical,
				Title: "Critical update", IssuedAt: &issuedA,
				CVEIDs:          []string{"CVE-2026-23456", "CVE-2026-23456"},
				References:      []dnf.AdvisoryReference{reference, reference},
				AffectedUpdates: []dnf.NEVRA{shared, {Name: "shared", Epoch: "0", Version: "1.0", Release: "1", Arch: "x86_64"}},
			},
			{
				ID: "FEDORA-2026-C", Type: "security", Severity: dnf.AdvisorySeverityModerate,
				Title: "Moderate update", IssuedAt: &issuedC,
				AffectedUpdates: []dnf.NEVRA{{Name: "moderate-pkg", Version: "4", Release: "2", Arch: "x86_64"}},
			},
			{
				ID: "FEDORA-2026-A", Type: "security", Severity: dnf.AdvisorySeverityCritical,
				Title: "Critical update", IssuedAt: &issuedA,
				CVEIDs: []string{"CVE-2026-12345"}, References: []dnf.AdvisoryReference{reference},
				AffectedUpdates: []dnf.NEVRA{example},
			},
		},
	}
}

func severityTotal(counts results.AdvisorySeverityCounts) int {
	return counts.Critical + counts.Important + counts.Moderate + counts.Low + counts.Unknown
}
