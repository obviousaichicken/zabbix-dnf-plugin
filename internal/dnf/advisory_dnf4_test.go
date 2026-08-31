package dnf

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseDNF4AdvisoryListFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version      string
		wantIDs      []string
		wantPackages int
	}{
		{version: "4.7", wantIDs: []string{"RLSA-2024:8922", "RLSA-2025:0733", "RLSA-2026:43420", "RLSA-2026:57462"}, wantPackages: 4},
		{version: "4.14", wantIDs: []string{"RLSA-2024:2512", "RLSA-2026:55439", "RLSA-2026:60226"}, wantPackages: 3},
		{version: "4.20", wantIDs: []string{"RLSA-2026:55432", "RLSA-2026:57015", "RLSA-2026:59380"}, wantPackages: 3},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()

			data := readAdvisoryFixture(t, "dnf4-"+test.version+"-list.txt")
			got, err := ParseDNF4AdvisoryList(data)
			if err != nil {
				t.Fatalf("ParseDNF4AdvisoryList() error = %v", err)
			}
			ids := make([]string, 0, len(got))
			packages := 0
			for _, advisory := range got {
				ids = append(ids, advisory.ID)
				packages += len(advisory.AffectedUpdates)
				if advisory.Type != "security" || advisory.Severity == AdvisorySeverityUnknown {
					t.Errorf("advisory %q = %#v, want classified security", advisory.ID, advisory)
				}
				if advisory.CVEIDs == nil || advisory.References == nil || advisory.AffectedUpdates == nil {
					t.Errorf("advisory %q has nil arrays", advisory.ID)
				}
			}
			if !slices.Equal(ids, test.wantIDs) || packages != test.wantPackages {
				t.Fatalf("fixture advisories = %v / %d packages, want %v / %d", ids, packages, test.wantIDs, test.wantPackages)
			}
		})
	}
}

func TestParseDNF4AdvisoryListMergesAndSorts(t *testing.T) {
	t.Parallel()

	data := []byte(`
TEST-2 None/Sec. zlib-1.3-2.x86_64
TEST-1 Critical/Sec. pkg-b-1.0-1.noarch
TEST-1 Critical/Sec. pkg-a-1.0-1.x86_64
TEST-1 Critical/Sec. pkg-a-0:1.0-1.x86_64
TEST-1 Critical/Sec. pkg-a-1.0-1.x86_64
TEST-3 NewVendorLevel/Sec. other-1.0-1.i686
`)

	got, err := ParseDNF4AdvisoryList(data)
	if err != nil {
		t.Fatalf("ParseDNF4AdvisoryList() error = %v", err)
	}
	if len(got) != 3 || got[0].ID != "TEST-1" || got[1].ID != "TEST-2" || got[2].ID != "TEST-3" {
		t.Fatalf("ParseDNF4AdvisoryList() IDs = %#v, want sorted TEST-1..3", got)
	}
	if got[0].Severity != AdvisorySeverityCritical || len(got[0].AffectedUpdates) != 2 {
		t.Fatalf("TEST-1 = %#v, want critical with two unique packages", got[0])
	}
	if got[0].AffectedUpdates[0].String() != "pkg-a-0:1.0-1.x86_64" ||
		got[0].AffectedUpdates[1].String() != "pkg-b-1.0-1.noarch" {
		t.Fatalf("TEST-1 packages = %#v, want canonical sorted packages", got[0].AffectedUpdates)
	}
	if got[1].Severity != AdvisorySeverityUnknown || got[2].Severity != AdvisorySeverityUnknown {
		t.Fatalf("None/new severities = %v/%v, want unknown", got[1].Severity, got[2].Severity)
	}
}

func TestParseDNF4AdvisoryListRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []string{
		"truncated\n",
		"ID Important/Bug. pkg-1.0-1.x86_64\n",
		"bad/id Important/Sec. pkg-1.0-1.x86_64\n",
		"ID Important/Sec. malformed\n",
		"ID Important/Sec. pkg-1.0-1.x86_64\nID Low/Sec. pkg-1.0-2.x86_64\n",
		strings.Repeat("x", 70<<10) + "\n",
	}

	for _, data := range tests {
		_, err := ParseDNF4AdvisoryList([]byte(data))
		if err == nil || !errors.Is(err, errInvalidDNF4AdvisoryList) {
			t.Errorf("ParseDNF4AdvisoryList(%q) error = %v, want invalid list", truncateTestValue(data), err)
		}
	}
}

func TestParseDNF4AdvisoryInfoFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		version   string
		wantID    string
		wantTitle string
		wantCVEs  []string
		wantDate  string
	}{
		{version: "4.7", wantID: "RLSA-2026:43420", wantTitle: "acl security update", wantCVEs: []string{"CVE-2026-54369", "CVE-2026-54370"}, wantDate: "2026-08-06T06:09:49Z"},
		{version: "4.14", wantID: "RLSA-2026:55439", wantTitle: "curl security update", wantCVEs: []string{"CVE-2026-1965", "CVE-2026-3783", "CVE-2026-8286", "CVE-2026-9547"}, wantDate: "2026-08-29T00:11:36Z"},
		{version: "4.20", wantID: "RLSA-2026:55432", wantTitle: "curl security update", wantCVEs: []string{"CVE-2026-8927"}, wantDate: "2026-08-29T06:14:12Z"},
	}

	for _, test := range tests {
		t.Run(test.version, func(t *testing.T) {
			t.Parallel()

			got, err := ParseDNF4AdvisoryInfo(readAdvisoryFixture(t, "dnf4-"+test.version+"-info.txt"))
			if err != nil {
				t.Fatalf("ParseDNF4AdvisoryInfo() error = %v", err)
			}
			if len(got) != 1 {
				t.Fatalf("ParseDNF4AdvisoryInfo() returned %d records, want 1", len(got))
			}
			advisory := got[0]
			if advisory.ID != test.wantID || advisory.Title != test.wantTitle ||
				advisory.Type != "security" || advisory.Severity != AdvisorySeverityImportant ||
				!slices.Equal(advisory.CVEIDs, test.wantCVEs) {
				t.Fatalf("parsed advisory = %#v, want ID/title/type/severity/CVEs from fixture", advisory)
			}
			if advisory.UpdatedAt == nil || advisory.UpdatedAt.Format(time.RFC3339) != test.wantDate || advisory.IssuedAt != nil {
				t.Fatalf("parsed timestamps = %v/%v, want updated %s and no issued", advisory.IssuedAt, advisory.UpdatedAt, test.wantDate)
			}
		})
	}
}

func TestParseDNF4AdvisoryInfoHandlesMultipleRecords(t *testing.T) {
	t.Parallel()

	data := []byte(`
===============================================================================
  Critical: Z title
===============================================================================
  Update ID: TEST-Z
       Type: security
    Updated:
       CVEs: CVE-2026-9999, CVE-2026-9999
Description: Text mentioning CVE-2026-0000 must not become structured data.
           : Another CVE-2026-0001 description line.
   Severity: Critical
===============================================================================
  None: A title
===============================================================================
  Update ID: TEST-A
       Type: security
    Updated: 2026-08-01 01:02:03
       CVEs:
   Severity: None
`)

	got, err := ParseDNF4AdvisoryInfo(data)
	if err != nil {
		t.Fatalf("ParseDNF4AdvisoryInfo() error = %v", err)
	}
	if len(got) != 2 || got[0].ID != "TEST-A" || got[1].ID != "TEST-Z" {
		t.Fatalf("records = %#v, want sorted TEST-A/TEST-Z", got)
	}
	if got[0].Title != "A title" || got[0].Severity != AdvisorySeverityUnknown || got[0].UpdatedAt == nil {
		t.Fatalf("TEST-A = %#v, want title, unknown severity, and timestamp", got[0])
	}
	if got[1].Title != "Z title" || !slices.Equal(got[1].CVEIDs, []string{"CVE-2026-9999"}) || got[1].UpdatedAt != nil {
		t.Fatalf("TEST-Z = %#v, want deduplicated field CVE and missing timestamp", got[1])
	}
}

func TestParseDNF4AdvisoryInfoRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []string{
		"Update ID: TEST-1\nSeverity: Important\n",
		"Update ID: TEST-1\nType: bugfix\n",
		"Update ID: bad/id\nType: security\n",
		"Update ID: TEST-1\nType: security\nUpdated: yesterday\n",
		"Update ID: TEST-1\nType: security\nSeverity: Low\nUpdate ID: TEST-1\nType: security\nSeverity: Critical\n",
		strings.Repeat("x", 70<<10) + ": value\n",
	}

	for _, data := range tests {
		_, err := ParseDNF4AdvisoryInfo([]byte(data))
		if err == nil || !errors.Is(err, errInvalidDNF4AdvisoryInfo) {
			t.Errorf("ParseDNF4AdvisoryInfo(%q) error = %v, want invalid info", truncateTestValue(data), err)
		}
	}
}

func TestParseDNF4AdvisoryParsersReturnEmptyArrays(t *testing.T) {
	t.Parallel()

	list, err := ParseDNF4AdvisoryList(nil)
	if err != nil || list == nil || len(list) != 0 {
		t.Fatalf("empty list = %#v, %v; want nonnil empty", list, err)
	}
	info, err := ParseDNF4AdvisoryInfo(nil)
	if err != nil || info == nil || len(info) != 0 {
		t.Fatalf("empty info = %#v, %v; want nonnil empty", info, err)
	}
}

func TestSecurityAdvisoriesDNF4CommandContract(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: []byte("4.14.0\n")},
		{stdout: readAdvisoryFixture(t, "dnf4-4.14-list.txt")},
	}}
	client := &Client{runner: runner, path: "/usr/bin/dnf"}
	started := time.Now().UTC()

	got, err := client.SecurityAdvisories(context.Background())
	if err != nil {
		t.Fatalf("SecurityAdvisories() error = %v", err)
	}
	if got.CollectedAt.Before(started) || got.CollectedAt.After(time.Now().UTC()) {
		t.Fatalf("CollectedAt = %s, want current UTC time", got.CollectedAt)
	}
	if got.Capabilities != (AdvisoryCapabilities{}) || len(got.Advisories) != 3 {
		t.Fatalf("SecurityAdvisories() = %#v, want three incomplete DNF4 advisories", got)
	}

	wantArgs := [][]string{
		{"--assumeno", "--version"},
		{"--assumeno", "-q", "--setopt=*.skip_if_unavailable=False", "updateinfo", "list", "--updates", "--security"},
	}
	if len(runner.requests) != len(wantArgs) {
		t.Fatalf("SecurityAdvisories() ran %d commands, want %d", len(runner.requests), len(wantArgs))
	}
	for index, request := range runner.requests {
		if !slices.Equal(request.Args, wantArgs[index]) {
			t.Errorf("request[%d] args = %q, want %q", index, request.Args, wantArgs[index])
		}
		if request.Env["LC_ALL"] != "C" || request.Env["LANG"] != "C" {
			t.Errorf("request[%d] locale = %#v, want C", index, request.Env)
		}
		if slices.Contains(request.Args, "info") {
			t.Errorf("request[%d] unexpectedly executed detail command", index)
		}
	}
}

func TestSecurityAdvisoriesDNF4ReturnsErrors(t *testing.T) {
	t.Parallel()

	commandErr := errors.New("command failed")
	tests := []struct {
		name      string
		responses []fakeResponse
		wantCause error
		wantText  string
	}{
		{name: "version", responses: []fakeResponse{{err: commandErr}}, wantCause: commandErr, wantText: "read DNF version"},
		{name: "list command", responses: []fakeResponse{{stdout: []byte("4.14.0")}, {err: commandErr}}, wantCause: commandErr, wantText: "list DNF4"},
		{name: "list parse", responses: []fakeResponse{{stdout: []byte("4.14.0")}, {stdout: []byte("bad")}}, wantText: "parse DNF4"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &Client{runner: &fakeRunner{responses: test.responses}, path: "/usr/bin/dnf"}
			got, err := client.SecurityAdvisories(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("SecurityAdvisories() error = %v, want text %q", err, test.wantText)
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("SecurityAdvisories() error = %v, want cause %v", err, test.wantCause)
			}
			if !reflect.DeepEqual(got, AdvisoryData{}) {
				t.Fatalf("SecurityAdvisories() = %#v, want zero data", got)
			}
		})
	}
}

func readAdvisoryFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", "advisories", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}

	return data
}

func truncateTestValue(value string) string {
	const limit = 80
	if len(value) <= limit {
		return value
	}

	return value[:limit] + "..."
}
