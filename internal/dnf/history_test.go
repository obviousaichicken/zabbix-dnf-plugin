//nolint:testpackage // history tests exercise the DNF adapter directly.
package dnf

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

type historyResponse struct {
	stdout []byte
	err    error
}

type historyRunner struct {
	responses []historyResponse
	requests  []command.Request
}

func (r *historyRunner) Run(
	_ context.Context,
	request command.Request,
) (command.Result, error) {
	r.requests = append(r.requests, request)
	response := r.responses[len(r.requests)-1]

	return command.Result{
		Stdout:   response.stdout,
		Stderr:   nil,
		ExitCode: 0,
	}, response.err
}

func TestLastUpdateReadsDNFHistory(t *testing.T) {
	t.Parallel()

	runner := &historyRunner{
		responses: []historyResponse{
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
		runner: &historyRunner{
			responses: []historyResponse{
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

	runner := &historyRunner{
		responses: []historyResponse{
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

	runner := &historyRunner{
		responses: []historyResponse{
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

func TestLastUpdateSkipsUnfinishedTransactions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		responses    []historyResponse
		want         time.Time
		wantRequests int
	}{
		{
			name: "DNF4 text",
			responses: []historyResponse{
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
			responses: []historyResponse{
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
			responses: []historyResponse{
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

			runner := &historyRunner{responses: test.responses}
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
	runner := &historyRunner{
		responses: []historyResponse{
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
