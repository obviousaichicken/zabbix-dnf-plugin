package dnf

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParseDNF5AdvisoryFixtures(t *testing.T) {
	t.Parallel()

	t.Run("5.2 object details", func(t *testing.T) {
		t.Parallel()

		version := mustDNF5Version(t, "5.2.18.0")
		got, capabilities, err := parseDNF5Advisories(
			readAdvisoryFixture(t, "dnf5-5.2-list.json"),
			readAdvisoryFixture(t, "dnf5-5.2-info.json"),
			version,
		)
		if err != nil {
			t.Fatalf("parseDNF5Advisories() error = %v", err)
		}
		if capabilities != (AdvisoryCapabilities{}) {
			t.Fatalf("capabilities = %#v, want incomplete because one list advisory has no detail", capabilities)
		}
		if len(got) != 2 || got[0].ID != "FEDORA-2026-11d7d4d8f3" || got[1].ID != "FEDORA-2026-6c99aaa6d3" {
			t.Fatalf("advisories = %#v, want two sorted applicable records", got)
		}
		if got[0].Title != "" || got[0].IssuedAt != nil || len(got[0].AffectedUpdates) != 1 ||
			got[0].AffectedUpdates[0].String() != "vim-data-2:9.2.390-1.fc42.noarch" {
			t.Fatalf("list-only advisory = %#v", got[0])
		}

		detail := got[1]
		if detail.Title != "krb5-1.21.3-7.fc42" || detail.Severity != AdvisorySeverityImportant ||
			!slices.Equal(detail.CVEIDs, []string{"CVE-2026-40355", "CVE-2026-40356"}) {
			t.Fatalf("enriched advisory = %#v, want normalized title/severity/CVEs", detail)
		}
		if detail.IssuedAt == nil || detail.IssuedAt.Format(time.RFC3339) != "2026-05-14T04:02:29Z" {
			t.Fatalf("issued timestamp = %v, want fixture UTC timestamp", detail.IssuedAt)
		}
		if len(detail.AffectedUpdates) != 1 || detail.AffectedUpdates[0].String() != "krb5-libs-1.21.3-7.fc42.x86_64" {
			t.Fatalf("affected packages = %#v, want only list-applicable x86_64 binary", detail.AffectedUpdates)
		}
		if len(detail.References) != 1 || detail.References[0].Type != "bugzilla" || detail.References[0].ID != "2463395" {
			t.Fatalf("references = %#v, want normalized vendor reference", detail.References)
		}
	})

	t.Run("5.3 array details", func(t *testing.T) {
		t.Parallel()

		version := mustDNF5Version(t, "5.4.3.0")
		got, capabilities, err := parseDNF5Advisories(
			readAdvisoryFixture(t, "dnf5-5.3-list.json"),
			readAdvisoryFixture(t, "dnf5-5.3-info.json"),
			version,
		)
		if err != nil {
			t.Fatalf("parseDNF5Advisories() error = %v", err)
		}
		wantCapabilities := AdvisoryCapabilities{DetailsComplete: true, CVEsComplete: true, IssueDatesComplete: true}
		if capabilities != wantCapabilities {
			t.Fatalf("capabilities = %#v, want %#v", capabilities, wantCapabilities)
		}
		if len(got) != 1 {
			t.Fatalf("advisories = %#v, want one merged advisory", got)
		}
		advisory := got[0]
		if advisory.ID != "FEDORA-2026-2f88b83676" || advisory.Title != "curl-8.18.0-9.fc44" ||
			!slices.Equal(advisory.CVEIDs, []string{"CVE-2026-8286", "CVE-2026-8925"}) {
			t.Fatalf("advisory = %#v, want fixture details", advisory)
		}
		if advisory.IssuedAt == nil || advisory.IssuedAt.Format(time.RFC3339) != "2026-08-27T00:54:36Z" {
			t.Fatalf("issued timestamp = %v, want integer Unix timestamp", advisory.IssuedAt)
		}
		wantPackages := []string{"curl-8.18.0-9.fc44.x86_64", "libcurl-8.18.0-9.fc44.x86_64"}
		gotPackages := []string{advisory.AffectedUpdates[0].String(), advisory.AffectedUpdates[1].String()}
		if !slices.Equal(gotPackages, wantPackages) {
			t.Fatalf("affected packages = %v, want %v", gotPackages, wantPackages)
		}
	})
}

func TestParseDNF5AdvisoriesAcceptsAdditiveFieldsAndStrictCVEFallback(t *testing.T) {
	t.Parallel()

	list := []byte(`[
  {"name":"TEST-1","type":"security","severity":"Future","nevra":"pkg-1.0-1.x86_64","buildtime":1787792076,"new_field":{"nested":true}}
]`)
	info := []byte(`[
  {
    "Name":"TEST-1","Title":"Test update","Severity":"Future","Type":"security","Issued":1787792076,
    "Description":"Fallback CVE-2026-1002; reject CVE-26-1 and CVE-2026-123x.",
    "references":[
      {"Type":"cve","Id":"CVE-2026-1000","Title":"structured","Url":"https://vendor.invalid/cve","extra":1},
      {"Type":"bugzilla","Id":"1","Title":"Misclassified CVE-2026-1001","Url":"https://vendor.invalid/bug"}
    ],
    "collections":{"packages":["pkg-0:1.0-1.x86_64","pkg-1.0-1.src"],"extra":true},
    "new_top_level":[1,2,3]
  }
]`)

	got, capabilities, err := parseDNF5Advisories(list, info, mustDNF5Version(t, "5.3.0"))
	if err != nil {
		t.Fatalf("parseDNF5Advisories() error = %v", err)
	}
	if capabilities != (AdvisoryCapabilities{DetailsComplete: true, CVEsComplete: true, IssueDatesComplete: true}) {
		t.Fatalf("capabilities = %#v, want complete", capabilities)
	}
	if len(got) != 1 || got[0].Severity != AdvisorySeverityUnknown ||
		!slices.Equal(got[0].CVEIDs, []string{"CVE-2026-1000", "CVE-2026-1001", "CVE-2026-1002"}) {
		t.Fatalf("advisories = %#v, want unknown severity and strict structured/fallback CVEs", got)
	}
	if len(got[0].AffectedUpdates) != 1 || got[0].AffectedUpdates[0].String() != "pkg-1.0-1.x86_64" {
		t.Fatalf("affected updates = %#v, detail added an unrelated package", got[0].AffectedUpdates)
	}
}

func TestParseDNF5AdvisoriesReportsPartialDetail(t *testing.T) {
	t.Parallel()

	list := []byte(`[
  {"name":"TEST-1","type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1787792076}
]`)
	info := []byte(`[
  {"Name":"TEST-1","Title":"","Severity":"Low","Type":"security","Issued":null,"references":[],"collections":{"packages":["other-1-1.x86_64"]}},
  {"Name":"UNRELATED-1","Title":"Other","Severity":"Low","Type":"security","Issued":1787792076,"references":[],"collections":{"packages":["other-1-1.src"]}}
]`)

	got, capabilities, err := parseDNF5Advisories(list, info, mustDNF5Version(t, "5.3.0"))
	if err != nil {
		t.Fatalf("parseDNF5Advisories() error = %v", err)
	}
	if capabilities.DetailsComplete || !capabilities.CVEsComplete || capabilities.IssueDatesComplete {
		t.Fatalf("capabilities = %#v, want partial title/package/date and complete CVE detail", capabilities)
	}
	if len(got) != 1 || got[0].ID != "TEST-1" || got[0].AffectedUpdates[0].Name != "pkg" {
		t.Fatalf("advisories = %#v, unrelated detail changed applicability", got)
	}
}

func TestParseDNF5AdvisoryTopLevelShapes(t *testing.T) {
	t.Parallel()

	version52 := mustDNF5Version(t, "5.2.18.0")
	version53 := mustDNF5Version(t, "5.3.0")

	for _, test := range []struct {
		name string
		run  func() error
		want error
	}{
		{name: "list object", run: func() error { _, err := parseDNF5AdvisoryList([]byte(`{}`), version52); return err }, want: errInvalidDNF5AdvisoryList},
		{name: "list null", run: func() error { _, err := parseDNF5AdvisoryList([]byte(`null`), version53); return err }, want: errInvalidDNF5AdvisoryList},
		{name: "5.2 info array", run: func() error { _, err := parseDNF5AdvisoryInfo([]byte(`[]`), version52); return err }, want: errInvalidDNF5AdvisoryInfo},
		{name: "5.3 info object", run: func() error { _, err := parseDNF5AdvisoryInfo([]byte(`{}`), version53); return err }, want: errInvalidDNF5AdvisoryInfo},
		{name: "empty list", run: func() error { _, err := parseDNF5AdvisoryList(nil, version53); return err }, want: errInvalidDNF5AdvisoryList},
		{name: "trailing JSON", run: func() error { _, err := parseDNF5AdvisoryInfo([]byte(`[] text`), version53); return err }, want: errInvalidDNF5AdvisoryInfo},
		{name: "wrong version", run: func() error {
			_, err := parseDNF5AdvisoryList([]byte(`[]`), DNFVersion{Major: 4, Minor: 20})
			return err
		}, want: errInvalidDNF5AdvisoryList},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if err := test.run(); err == nil || !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestParseDNF5AdvisoryListRejectsInvalidRecords(t *testing.T) {
	t.Parallel()

	version52 := mustDNF5Version(t, "5.2.18.0")
	version53 := mustDNF5Version(t, "5.3.0")
	tests := []struct {
		name    string
		version DNFVersion
		data    string
	}{
		{name: "missing ID", version: version53, data: `[{"type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1}]`},
		{name: "invalid ID", version: version53, data: `[{"name":"bad/id","type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1}]`},
		{name: "nonsecurity type", version: version53, data: `[{"name":"TEST","type":"bugfix","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1}]`},
		{name: "malformed package", version: version53, data: `[{"name":"TEST","type":"security","severity":"Low","nevra":"bad","buildtime":1}]`},
		{name: "5.2 number timestamp", version: version52, data: `[{"name":"TEST","type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1}]`},
		{name: "5.3 string timestamp", version: version53, data: `[{"name":"TEST","type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":"2026-01-01 00:00:00"}]`},
		{name: "5.3 fractional timestamp", version: version53, data: `[{"name":"TEST","type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1.5}]`},
		{name: "conflicting duplicate", version: version53, data: `[
          {"name":"TEST","type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1},
          {"name":"TEST","type":"security","severity":"Critical","nevra":"pkg-2-1.x86_64","buildtime":1}
        ]`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseDNF5AdvisoryList([]byte(test.data), test.version)
			if err == nil || !errors.Is(err, errInvalidDNF5AdvisoryList) {
				t.Fatalf("parseDNF5AdvisoryList() error = %v, want invalid list", err)
			}
		})
	}
}

func TestParseDNF5AdvisoryInfoRejectsInvalidRecords(t *testing.T) {
	t.Parallel()

	version52 := mustDNF5Version(t, "5.2.18.0")
	version53 := mustDNF5Version(t, "5.3.0")
	tests := []struct {
		name    string
		version DNFVersion
		data    string
	}{
		{name: "5.2 missing Name", version: version52, data: `{"TEST":{"Type":"security","Severity":"Low","Issued":"2026-01-01 00:00:00"}}`},
		{name: "5.2 key mismatch", version: version52, data: `{"TEST":{"Name":"OTHER","Type":"security","Severity":"Low","Issued":"2026-01-01 00:00:00"}}`},
		{name: "5.3 missing ID", version: version53, data: `[{"Type":"security","Severity":"Low","Issued":1}]`},
		{name: "invalid type", version: version53, data: `[{"Name":"TEST","Type":"bugfix","Severity":"Low","Issued":1}]`},
		{name: "invalid issued", version: version52, data: `{"TEST":{"Name":"TEST","Type":"security","Severity":"Low","Issued":"yesterday"}}`},
		{name: "invalid updated", version: version53, data: `[{"Name":"TEST","Type":"security","Severity":"Low","Issued":1,"Updated":"bad"}]`},
		{name: "malformed package", version: version53, data: `[{"Name":"TEST","Type":"security","Severity":"Low","Issued":1,"collections":{"packages":["bad"]}}]`},
		{name: "malformed unrelated package", version: version53, data: `[{"Name":"UNRELATED","Type":"security","Severity":"Low","Issued":1,"collections":{"packages":["bad"]}}]`},
		{name: "conflicting duplicate", version: version53, data: `[
          {"Name":"TEST","Title":"one","Type":"security","Severity":"Low","Issued":1},
          {"Name":"TEST","Title":"two","Type":"security","Severity":"Low","Issued":1}
        ]`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseDNF5AdvisoryInfo([]byte(test.data), test.version)
			if err == nil || !errors.Is(err, errInvalidDNF5AdvisoryInfo) {
				t.Fatalf("parseDNF5AdvisoryInfo() error = %v, want invalid info", err)
			}
		})
	}
}

func TestParseDNF5AdvisoriesRejectsClassificationConflict(t *testing.T) {
	t.Parallel()

	list := []byte(`[{"name":"TEST","type":"security","severity":"Low","nevra":"pkg-1-1.x86_64","buildtime":1}]`)
	info := []byte(`[{"Name":"TEST","Title":"Test","Type":"security","Severity":"Critical","Issued":1,"collections":{"packages":["pkg-1-1.x86_64"]}}]`)
	_, _, err := parseDNF5Advisories(list, info, mustDNF5Version(t, "5.3.0"))
	if err == nil || !errors.Is(err, errInvalidDNF5AdvisoryData) {
		t.Fatalf("parseDNF5Advisories() error = %v, want classification conflict", err)
	}
}

func TestParseDNF5AdvisoriesEmptyArrays(t *testing.T) {
	t.Parallel()

	got, capabilities, err := parseDNF5Advisories(
		[]byte(`[]`),
		[]byte(`[]`),
		mustDNF5Version(t, "5.3.0"),
	)
	if err != nil {
		t.Fatalf("parseDNF5Advisories() error = %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Fatalf("advisories = %#v, want nonnil empty", got)
	}
	if capabilities != (AdvisoryCapabilities{DetailsComplete: true, CVEsComplete: true, IssueDatesComplete: true}) {
		t.Fatalf("capabilities = %#v, want successful empty collection complete", capabilities)
	}
}

func TestSecurityAdvisoriesDNF5CommandContract(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{responses: []fakeResponse{
		{stdout: []byte("dnf5 version 5.4.3.0\n")},
		{stdout: readAdvisoryFixture(t, "dnf5-5.3-list.json")},
		{stdout: readAdvisoryFixture(t, "dnf5-5.3-info.json")},
	}}
	client := &Client{runner: runner, path: "/usr/bin/dnf5"}
	started := time.Now().UTC()

	got, err := client.SecurityAdvisories(context.Background())
	if err != nil {
		t.Fatalf("SecurityAdvisories() error = %v", err)
	}
	if got.CollectedAt.Before(started) || got.CollectedAt.After(time.Now().UTC()) || len(got.Advisories) != 1 {
		t.Fatalf("SecurityAdvisories() = %#v, want current complete fixture data", got)
	}

	wantArgs := [][]string{
		{"--assumeno", "--version"},
		{"--assumeno", "-q", "--setopt=*.skip_if_unavailable=False", "advisory", "list", "--updates", "--security", "--json"},
		{"--assumeno", "-q", "--setopt=*.skip_if_unavailable=False", "advisory", "info", "--updates", "--security", "--json"},
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
	}
}

func TestSecurityAdvisoriesDNF5ReturnsErrors(t *testing.T) {
	t.Parallel()

	commandErr := errors.New("command failed")
	validList := readAdvisoryFixture(t, "dnf5-5.3-list.json")
	validInfo := readAdvisoryFixture(t, "dnf5-5.3-info.json")
	tests := []struct {
		name      string
		responses []fakeResponse
		wantCause error
		wantText  string
	}{
		{name: "version", responses: []fakeResponse{{err: commandErr}}, wantCause: commandErr, wantText: "read DNF version"},
		{name: "list command", responses: []fakeResponse{{stdout: []byte("dnf5 version 5.4.3.0")}, {err: commandErr}}, wantCause: commandErr, wantText: "list DNF5"},
		{name: "info command", responses: []fakeResponse{{stdout: []byte("dnf5 version 5.4.3.0")}, {stdout: validList}, {err: commandErr}}, wantCause: commandErr, wantText: "details"},
		{name: "list parse", responses: []fakeResponse{{stdout: []byte("dnf5 version 5.4.3.0")}, {stdout: []byte("text")}, {stdout: validInfo}}, wantCause: errInvalidDNF5AdvisoryList, wantText: "parse DNF5"},
		{name: "info parse", responses: []fakeResponse{{stdout: []byte("dnf5 version 5.4.3.0")}, {stdout: validList}, {stdout: []byte("text")}}, wantCause: errInvalidDNF5AdvisoryInfo, wantText: "parse DNF5"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &Client{runner: &fakeRunner{responses: test.responses}, path: "/usr/bin/dnf5"}
			got, err := client.SecurityAdvisories(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantText) || !errors.Is(err, test.wantCause) {
				t.Fatalf("SecurityAdvisories() error = %v, want text %q and cause %v", err, test.wantText, test.wantCause)
			}
			if !reflect.DeepEqual(got, AdvisoryData{}) {
				t.Fatalf("SecurityAdvisories() = %#v, want zero data", got)
			}
		})
	}
}

func mustDNF5Version(t *testing.T, value string) DNFVersion {
	t.Helper()

	version, err := ParseDNFVersion([]byte("dnf5 version " + value))
	if err != nil {
		t.Fatalf("ParseDNFVersion(%q) error = %v", value, err)
	}

	return version
}
