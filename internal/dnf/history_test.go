//nolint:testpackage // history tests exercise the DNF adapter directly.
package dnf

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLastUpdateReadsDNFHistory(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: []byte("4.14.0\n")},
			{stdout: []byte(
				"ID | Command line | Date and time | Action(s) | Altered\n" +
					" 7 | update -y | 2026-08-19 21:14 | Upgrade | 1\n",
			)},
			{stdout: []byte(
				"Transaction ID : 7\n" +
					"End time     : Wed Aug 19 21:14:08 2026 (1 seconds)\n" +
					"Return-Code  : Success\n" +
					"Packages Altered:\n" +
					"    Upgrade  bash-5.2.26-1.el9.x86_64\n",
			)},
		},
	}
	client := &Client{
		runner: runner,
		path:   "/usr/bin/dnf",
	}

	got, err := client.LastUpdate(context.Background())
	if err != nil {
		t.Fatalf("LastUpdate() error = %v", err)
	}
	if got == nil {
		t.Fatal("LastUpdate() = nil, want transaction")
	}

	wantTimestamp, err := time.ParseInLocation(
		"Mon Jan 2 15:04:05 2006",
		"Wed Aug 19 21:14:08 2026",
		time.Local,
	)
	if err != nil {
		t.Fatalf("parse expected timestamp: %v", err)
	}
	if !got.Timestamp.Equal(wantTimestamp.UTC()) {
		t.Fatalf("LastUpdate().Timestamp = %s, want %s", got.Timestamp, wantTimestamp.UTC())
	}
	if got.Result != "success" {
		t.Fatalf("LastUpdate().Result = %q, want %q", got.Result, "success")
	}
}

func TestLastUpdateReturnsNilForEmptyDNFHistory(t *testing.T) {
	t.Parallel()

	client := &Client{
		runner: &fakeRunner{
			responses: []fakeResponse{
				{stdout: []byte("4.14.0\n")},
				{stdout: nil},
			},
		},
		path: "/usr/bin/dnf",
	}

	got, err := client.LastUpdate(context.Background())
	if err != nil {
		t.Fatalf("LastUpdate() error = %v", err)
	}
	if got != nil {
		t.Fatalf("LastUpdate() = %#v, want nil", got)
	}
}

func TestLastUpdateReadsDNF5History(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: []byte("dnf5 version 5.4.2.1\n")},
			{stdout: []byte("[{\"id\":8},{\"id\":7}]")},
			{stdout: []byte(`[{"end_time":1787160000,"status":"Ok","packages":[{"action":"Remove"}]}]`)},
			{stdout: []byte(`[{"end_time":1787159648,"status":"Ok","packages":[{"action":"Upgrade"}]}]`)},
		},
	}
	client := &Client{
		runner: runner,
		path:   "/usr/bin/dnf",
	}

	got, err := client.LastUpdate(context.Background())
	if err != nil {
		t.Fatalf("LastUpdate() error = %v", err)
	}
	if got == nil {
		t.Fatal("LastUpdate() = nil, want transaction")
	}

	wantTimestamp := time.Unix(1787159648, 0).UTC()
	if !got.Timestamp.Equal(wantTimestamp) {
		t.Fatalf("LastUpdate().Timestamp = %s, want %s", got.Timestamp, wantTimestamp)
	}
	if got.Result != "success" {
		t.Fatalf("LastUpdate().Result = %q, want %q", got.Result, "success")
	}
}

func TestParseDNF5HistoryInfoReturnsFailedUpgrade(t *testing.T) {
	t.Parallel()

	data := []byte(
		`[{"end_time":1787159648,"status":"Error","packages":[{"action":"Upgrade"}]}]`,
	)

	got, upgraded, err := parseDNF5HistoryInfo(data)
	if err != nil {
		t.Fatalf("parseDNF5HistoryInfo() error = %v", err)
	}
	if !upgraded {
		t.Fatal("parseDNF5HistoryInfo() upgraded = false, want true")
	}
	if got.Result != "failed" {
		t.Fatalf("parseDNF5HistoryInfo().Result = %q, want %q", got.Result, "failed")
	}
}

func TestLastUpdateReadsOlderDNF5History(t *testing.T) {
	t.Parallel()

	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: []byte("dnf5 version 5.2.18.0\n")},
			{stdout: []byte(
				"ID Command line Date and time Action(s) Altered\n" +
					" 3 dnf upgrade 2026-08-21 16:36:49 10\n",
			)},
			{stdout: []byte(
				"Transaction ID : 3\n" +
					"End time       : 2026-08-21 16:36:49\n" +
					"Status         : Ok\n" +
					"Packages altered:\n" +
					"  Upgrade  curl-8.15.0-8.fc43.x86_64\n",
			)},
		},
	}
	client := &Client{
		runner: runner,
		path:   "/usr/bin/dnf",
	}

	got, err := client.LastUpdate(context.Background())
	if err != nil {
		t.Fatalf("LastUpdate() error = %v", err)
	}
	if got == nil {
		t.Fatal("LastUpdate() = nil, want transaction")
	}
	if got.Result != "success" {
		t.Fatalf("LastUpdate().Result = %q, want %q", got.Result, "success")
	}
	for _, request := range runner.requests {
		for _, arg := range request.Args {
			if arg == "--json" {
				t.Fatalf("DNF 5.2 request unexpectedly used --json: %#v", request)
			}
		}
	}
}

func TestHistoryCapabilitiesRejectsMalformedDNF5Versions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		version     string
		wantErrText string
	}{
		{name: "missing minor version", version: "dnf5 version 5\n", wantErrText: `parse DNF5 version "5"`},
		{name: "invalid major version", version: "dnf5 version five.4.0\n", wantErrText: "major version"},
		{name: "invalid minor version", version: "dnf5 version 5.four.0\n", wantErrText: "minor version"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &Client{
				runner: &fakeRunner{responses: []fakeResponse{{stdout: []byte(test.version)}}},
				path:   "/usr/bin/dnf",
			}

			_, _, err := client.historyCapabilities(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantErrText) {
				t.Fatalf("historyCapabilities() error = %v, want text %q", err, test.wantErrText)
			}
		})
	}
}

func TestLastUpdateReturnsVersionQueryError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("version unavailable")
	client := &Client{
		runner: &fakeRunner{responses: []fakeResponse{{err: wantErr}}},
		path:   "/usr/bin/dnf",
	}

	got, err := client.LastUpdate(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("LastUpdate() error = %v, want %v", err, wantErr)
	}
	if got != nil {
		t.Fatalf("LastUpdate() = %#v, want nil", got)
	}
}

func TestLastUpdateReturnsNilWithoutUpgrade(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		responses    []fakeResponse
		wantRequests int
	}{
		{
			name: "DNF4 skips non-upgrade transaction",
			responses: []fakeResponse{
				{stdout: []byte("4.14.0\n")},
				{stdout: []byte(" 7 | remove -y | 2026-08-19 21:14 | Erase | 1\n")},
			},
			wantRequests: 2,
		},
		{
			name: "DNF5 JSON transaction has no upgrade",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.4.2.1\n")},
				{stdout: []byte(`[{"id":7}]`)},
				{stdout: []byte(`[{
					"end_time":1787159648,
					"status":"Ok",
					"packages":[{"action":"Remove"}]
				}]`)},
			},
			wantRequests: 3,
		},
		{
			name: "DNF5 text ignores non-transactions and removal",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.2.18.0\n")},
				{stdout: []byte("\nID Command line Date and time Action(s) Altered\n7 dnf remove\n")},
				{stdout: []byte(
					"End time : 2026-08-19 21:14:08\n" +
						"Status : Ok\n" +
						"Packages altered:\n" +
						" Remove curl-1.x86_64\n",
				)},
			},
			wantRequests: 3,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runner := &fakeRunner{responses: test.responses}
			client := &Client{runner: runner, path: "/usr/bin/dnf"}

			got, err := client.LastUpdate(context.Background())
			if err != nil {
				t.Fatalf("LastUpdate() error = %v", err)
			}
			if got != nil {
				t.Fatalf("LastUpdate() = %#v, want nil", got)
			}
			if len(runner.requests) != test.wantRequests {
				t.Fatalf("LastUpdate() ran %d commands, want %d", len(runner.requests), test.wantRequests)
			}
		})
	}
}

func TestParseDNF5HistoryInfoRequiresOneTransaction(t *testing.T) {
	t.Parallel()

	for _, data := range []string{"[]", "[{},{}]"} {
		_, _, err := parseDNF5HistoryInfo([]byte(data))
		if err == nil || !strings.Contains(err.Error(), "expected one transaction") {
			t.Fatalf("parseDNF5HistoryInfo(%q) error = %v, want transaction count error", data, err)
		}
	}
}

func TestParseTextHistoryInfoNormalizesFailedResult(t *testing.T) {
	t.Parallel()

	got, upgraded, err := parseTextHistoryInfo([]byte(
		"End time : 2026-08-19 21:14:08\n" +
			"Status : Error\n" +
			"Packages altered:\n" +
			" Upgrade curl-1.x86_64\n",
	))
	if err != nil {
		t.Fatalf("parseTextHistoryInfo() error = %v", err)
	}
	if !upgraded {
		t.Fatal("parseTextHistoryInfo() upgraded = false, want true")
	}
	if got.Result != LastUpdateResultFailed {
		t.Fatalf("parseTextHistoryInfo().Result = %q, want %q", got.Result, LastUpdateResultFailed)
	}
}

func TestLastUpdateReturnsHistoryErrors(t *testing.T) {
	t.Parallel()

	commandErr := errors.New("history command failed")
	tests := []struct {
		name      string
		responses []fakeResponse
		wantCause error
		wantText  string
	}{
		{
			name: "DNF4 list failure",
			responses: []fakeResponse{
				{stdout: []byte("4.14.0\n")},
				{err: commandErr},
			},
			wantCause: commandErr,
			wantText:  "list DNF history",
		},
		{
			name: "DNF4 detail failure",
			responses: []fakeResponse{
				{stdout: []byte("4.14.0\n")},
				{stdout: []byte(" 7 | update -y | 2026-08-19 21:14 | Upgrade | 1\n")},
				{err: commandErr},
			},
			wantCause: commandErr,
			wantText:  "inspect DNF transaction 7",
		},
		{
			name: "DNF4 malformed detail",
			responses: []fakeResponse{
				{stdout: []byte("4.14.0\n")},
				{stdout: []byte(" 7 | update -y | 2026-08-19 21:14 | Upgrade | 1\n")},
				{stdout: []byte(
					"End time : not-a-time\n" +
						"Return-Code : Success\n" +
						"Packages Altered:\n" +
						" Upgrade bash-1.x86_64\n",
				)},
			},
			wantText: "parse DNF transaction 7",
		},
		{
			name: "DNF5 JSON invalid list",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.4.2.1\n")},
				{stdout: []byte("not-json")},
			},
			wantText: "parse DNF5 history list",
		},
		{
			name: "DNF5 JSON invalid transaction ID",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.4.2.1\n")},
				{stdout: []byte(`[{"id":0}]`)},
			},
			wantText: "invalid transaction ID 0",
		},
		{
			name: "DNF5 JSON detail failure",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.4.2.1\n")},
				{stdout: []byte(`[{"id":7}]`)},
				{err: commandErr},
			},
			wantCause: commandErr,
			wantText:  "inspect DNF5 transaction 7",
		},
		{
			name: "DNF5 JSON malformed detail",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.4.2.1\n")},
				{stdout: []byte(`[{"id":7}]`)},
				{stdout: []byte("not-json")},
			},
			wantText: "parse DNF5 transaction 7",
		},
		{
			name: "DNF5 text list failure",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.2.18.0\n")},
				{err: commandErr},
			},
			wantCause: commandErr,
			wantText:  "list DNF5 history",
		},
		{
			name: "DNF5 text detail failure",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.2.18.0\n")},
				{stdout: []byte("7 dnf upgrade 2026-08-19 21:14:08 1\n")},
				{err: commandErr},
			},
			wantCause: commandErr,
			wantText:  "inspect DNF5 transaction 7",
		},
		{
			name: "DNF5 text malformed detail",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.2.18.0\n")},
				{stdout: []byte("7 dnf upgrade 2026-08-19 21:14:08 1\n")},
				{stdout: []byte(
					"End time : not-a-time\n" +
						"Status : Ok\n" +
						"Packages altered:\n" +
						" Upgrade curl-1.x86_64\n",
				)},
			},
			wantText: "parse DNF5 transaction 7",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &Client{
				runner: &fakeRunner{responses: test.responses},
				path:   "/usr/bin/dnf",
			}

			got, err := client.LastUpdate(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantText) {
				t.Fatalf("LastUpdate() error = %v, want text %q", err, test.wantText)
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("LastUpdate() error = %v, want cause %v", err, test.wantCause)
			}
			if got != nil {
				t.Fatalf("LastUpdate() = %#v, want nil", got)
			}
		})
	}
}

func TestLastUpdateSkipsUnfinishedTransactions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		responses    []fakeResponse
		want         time.Time
		wantRequests int
	}{
		{
			name: "DNF4 text",
			responses: []fakeResponse{
				{stdout: []byte("4.14.0\n")},
				{stdout: []byte(
					"ID | Command line | Date and time | Action(s) | Altered\n" +
						" 8 | update -y | 2026-08-20 10:00 | Upgrade | 1\n" +
						" 7 | update -y | 2026-08-19 21:14 | Upgrade | 1\n",
				)},
				{stdout: []byte(
					"Transaction ID : 8\n" +
						"Begin time    : Thu Aug 20 10:00:00 2026\n" +
						"Packages Altered:\n" +
						"    Upgrade  bash-5.2.27-1.el9.x86_64\n",
				)},
				{stdout: []byte(
					"Transaction ID : 7\n" +
						"End time     : Wed Aug 19 21:14:08 2026\n" +
						"Return-Code  : Success\n" +
						"Packages Altered:\n" +
						"    Upgrade  bash-5.2.26-1.el9.x86_64\n",
				)},
			},
			want:         time.Date(2026, time.August, 19, 21, 14, 8, 0, time.Local).UTC(),
			wantRequests: 4,
		},
		{
			name: "DNF5 JSON",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.4.2.1\n")},
				{stdout: []byte(`[{"id":8},{"id":7}]`)},
				{stdout: []byte(`[{"end_time":0,"status":"Started","packages":[{"action":"Upgrade"}]}]`)},
				{stdout: []byte(`[{"end_time":1787159648,"status":"Ok","packages":[{"action":"Upgrade"}]}]`)},
			},
			want:         time.Unix(1787159648, 0).UTC(),
			wantRequests: 4,
		},
		{
			name: "DNF5 text",
			responses: []fakeResponse{
				{stdout: []byte("dnf5 version 5.2.18.0\n")},
				{stdout: []byte(
					"ID Command line Date and time Action(s) Altered\n" +
						" 8 dnf upgrade 2026-08-20 10:00:00 1\n" +
						" 7 dnf upgrade 2026-08-19 21:14:08 1\n",
				)},
				{stdout: []byte(
					"Transaction ID : 8\n" +
						"Begin time      : 2026-08-20 10:00:00\n" +
						"Status          : Started\n" +
						"Packages altered:\n" +
						"  Upgrade  curl-8.16.0-1.fc43.x86_64\n",
				)},
				{stdout: []byte(
					"Transaction ID : 7\n" +
						"End time        : 2026-08-19 21:14:08\n" +
						"Status          : Ok\n" +
						"Packages altered:\n" +
						"  Upgrade  curl-8.15.0-8.fc43.x86_64\n",
				)},
			},
			want:         time.Date(2026, time.August, 19, 21, 14, 8, 0, time.Local).UTC(),
			wantRequests: 4,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runner := &fakeRunner{responses: test.responses}
			client := &Client{runner: runner, path: "/usr/bin/dnf"}

			got, err := client.LastUpdate(context.Background())
			if err != nil {
				t.Fatalf("LastUpdate() error = %v", err)
			}
			if got == nil {
				t.Fatal("LastUpdate() = nil, want completed transaction")
			}
			if !got.Timestamp.Equal(test.want) {
				t.Fatalf("LastUpdate().Timestamp = %s, want %s", got.Timestamp, test.want)
			}
			if got.Result != LastUpdateResultSuccess {
				t.Fatalf("LastUpdate().Result = %q, want %q", got.Result, LastUpdateResultSuccess)
			}
			if len(runner.requests) != test.wantRequests {
				t.Fatalf("LastUpdate() ran %d commands, want %d", len(runner.requests), test.wantRequests)
			}
		})
	}
}

func TestParseTextHistoryInfoRejectsInvalidCompletedTimestamp(t *testing.T) {
	t.Parallel()

	_, _, err := parseTextHistoryInfo([]byte(
		"End time        : not-a-time\n" +
			"Status          : Ok\n" +
			"Packages altered:\n" +
			"  Upgrade  curl-8.15.0-8.fc43.x86_64\n",
	))
	if err == nil {
		t.Fatal("parseTextHistoryInfo() error = nil, want invalid timestamp error")
	}
}

func TestHistoryParsersRejectCompletedTransactionsWithoutEndTime(t *testing.T) {
	t.Parallel()

	_, _, err := parseDNF5HistoryInfo([]byte(
		`[{"end_time":0,"status":"Ok","packages":[{"action":"Upgrade"}]}]`,
	))
	if err == nil {
		t.Fatal("parseDNF5HistoryInfo() error = nil, want missing end time error")
	}

	_, _, err = parseTextHistoryInfo([]byte(
		"Status          : Ok\n" +
			"Packages altered:\n" +
			"  Upgrade  curl-8.15.0-8.fc43.x86_64\n",
	))
	if err == nil {
		t.Fatal("parseTextHistoryInfo() error = nil, want missing end time error")
	}
}

func TestLastUpdateDoesNotFallbackAfterDNF5JSONFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("history unavailable")
	runner := &fakeRunner{
		responses: []fakeResponse{
			{stdout: []byte("dnf5 version 5.4.2.1\n")},
			{err: wantErr},
		},
	}
	client := &Client{runner: runner, path: "/usr/bin/dnf"}

	_, err := client.LastUpdate(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("LastUpdate() error = %v, want %v", err, wantErr)
	}
	if len(runner.requests) != 2 {
		t.Fatalf("LastUpdate() ran %d commands, want 2", len(runner.requests))
	}
}
