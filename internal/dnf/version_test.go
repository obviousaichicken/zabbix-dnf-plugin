package dnf

import (
	"context"
	"strings"
	"testing"
)

func TestParseDNFVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      string
		wantMajor  int
		wantMinor  int
		wantDNF5   bool
		wantString string
	}{
		{name: "DNF 4.7", input: "4.7.0\n", wantMajor: 4, wantMinor: 7, wantString: "4.7.0"},
		{name: "DNF 4 multiline", input: "4.20.0\n  Installed: dnf-4.20.0\n", wantMajor: 4, wantMinor: 20, wantString: "4.20.0"},
		{name: "DNF5 5.2", input: "dnf5 version 5.2.18.0\n", wantMajor: 5, wantMinor: 2, wantDNF5: true, wantString: "5.2.18.0"},
		{name: "DNF5 5.4", input: "dnf5 version 5.4.3.0\n", wantMajor: 5, wantMinor: 4, wantDNF5: true, wantString: "5.4.3.0"},
		{name: "future DNF5", input: "dnf5 version 6.0\n", wantMajor: 6, wantMinor: 0, wantDNF5: true, wantString: "6.0"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got, err := ParseDNFVersion([]byte(test.input))
			if err != nil {
				t.Fatalf("ParseDNFVersion() error = %v", err)
			}
			if got.Major != test.wantMajor || got.Minor != test.wantMinor ||
				got.DNF5 != test.wantDNF5 || got.String() != test.wantString {
				t.Fatalf("ParseDNFVersion() = %#v (%q), want major=%d minor=%d dnf5=%t string=%q", got, got.String(), test.wantMajor, test.wantMinor, test.wantDNF5, test.wantString)
			}
		})
	}
}

func TestParseDNFVersionRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		wantErr string
	}{
		{input: "", wantErr: "output is empty"},
		{input: "4", wantErr: "major and minor"},
		{input: "dnf5 version", wantErr: "version is missing"},
		{input: "dnf5 version 5", wantErr: "DNF5 version"},
		{input: "five.4", wantErr: "major version"},
		{input: "4.four", wantErr: "minor version"},
		{input: "5..4", wantErr: "minor version"},
		{input: "5.4.", wantErr: "empty component"},
		{input: "5.4.beta", wantErr: "component"},
		{input: "dnf5 version 4.20.0", wantErr: "below 5"},
		{input: "dnf5 version 5.-1.0", wantErr: "minor version"},
		{input: "dnf5 version 4294967296.0", wantErr: "major version"},
	}

	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			t.Parallel()

			_, err := ParseDNFVersion([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("ParseDNFVersion(%q) error = %v, want %q", test.input, err, test.wantErr)
			}
		})
	}
}

func TestDNFVersionAtLeast(t *testing.T) {
	t.Parallel()

	version := DNFVersion{Major: 5, Minor: 4}
	for _, test := range []struct {
		major int
		minor int
		want  bool
	}{
		{major: 5, minor: 3, want: true},
		{major: 5, minor: 4, want: true},
		{major: 5, minor: 5, want: false},
		{major: 4, minor: 99, want: true},
		{major: 6, minor: 0, want: false},
	} {
		if got := version.AtLeast(test.major, test.minor); got != test.want {
			t.Errorf("AtLeast(%d, %d) = %t, want %t", test.major, test.minor, got, test.want)
		}
	}
}

func TestClientCapabilities(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		output          string
		wantDNF5        bool
		wantHistoryJSON bool
	}{
		{name: "DNF4", output: "4.20.0\n"},
		{name: "legacy malformed DNF4 output", output: "legacy output\n"},
		{name: "DNF5 before history JSON", output: "dnf5 version 5.2.18.0\n", wantDNF5: true},
		{name: "DNF5 with history JSON", output: "dnf5 version 5.4.0.0\n", wantDNF5: true, wantHistoryJSON: true},
		{name: "future DNF5", output: "dnf5 version 6.0.0\n", wantDNF5: true, wantHistoryJSON: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			runner := &fakeRunner{responses: []fakeResponse{{stdout: []byte(test.output)}}}
			client := &Client{runner: runner, path: "/usr/bin/dnf"}
			got, err := client.capabilities(context.Background())
			if err != nil {
				t.Fatalf("capabilities() error = %v", err)
			}
			if got.DNF5 != test.wantDNF5 || got.HistoryJSON != test.wantHistoryJSON {
				t.Fatalf("capabilities() = %#v, want dnf5=%t historyJSON=%t", got, test.wantDNF5, test.wantHistoryJSON)
			}
			if len(runner.requests) != 1 || strings.Join(runner.requests[0].Args, " ") != "--assumeno --version" {
				t.Fatalf("capabilities() requests = %#v, want one version query", runner.requests)
			}
		})
	}
}
