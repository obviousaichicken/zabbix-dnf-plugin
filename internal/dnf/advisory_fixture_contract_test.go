package dnf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var dnf4FixtureVersions = []string{"4.7", "4.14", "4.20"}

func TestDNFAdvisoryFormatFixtures(t *testing.T) {
	t.Parallel()

	for _, version := range dnf4FixtureVersions {
		version := version
		t.Run("dnf4-"+version, func(t *testing.T) {
			t.Parallel()

			for _, suffix := range []string{"list.txt", "info.txt"} {
				data, err := os.ReadFile(filepath.Join("testdata", "advisories", "dnf4-"+version+"-"+suffix))
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				if len(strings.TrimSpace(string(data))) == 0 {
					t.Fatal("fixture is empty")
				}
			}
		})
	}

	for _, family := range []string{"5.2", "5.3"} {
		family := family
		t.Run("dnf5-"+family, func(t *testing.T) {
			t.Parallel()

			for _, suffix := range []string{"list.json", "info.json"} {
				data, err := os.ReadFile(filepath.Join("testdata", "advisories", "dnf5-"+family+"-"+suffix))
				if err != nil {
					t.Fatalf("read fixture: %v", err)
				}
				if !json.Valid(data) {
					t.Fatalf("fixture is not valid JSON: %s", data)
				}
			}
		})
	}
}

func FuzzDNF4AdvisoryContract(f *testing.F) {
	for _, version := range dnf4FixtureVersions {
		for _, suffix := range []string{"list.txt", "info.txt"} {
			data, err := os.ReadFile(filepath.Join("testdata", "advisories", "dnf4-"+version+"-"+suffix))
			if err != nil {
				f.Fatalf("read seed: %v", err)
			}
			f.Add(suffix, string(data))
		}
	}

	f.Fuzz(func(t *testing.T, kind, input string) {
		if len(input) > 8<<20 {
			t.Skip()
		}
		switch kind {
		case "list.txt":
			_, _ = ParseDNF4AdvisoryList([]byte(input))
		case "info.txt":
			_, _ = ParseDNF4AdvisoryInfo([]byte(input))
		}
	})
}

func FuzzDNF5AdvisoryContract(f *testing.F) {
	for _, family := range []string{"5.2", "5.3"} {
		for _, suffix := range []string{"list.json", "info.json"} {
			data, err := os.ReadFile(filepath.Join("testdata", "advisories", "dnf5-"+family+"-"+suffix))
			if err != nil {
				f.Fatalf("read seed: %v", err)
			}
			f.Add(family, suffix, string(data))
		}
	}

	f.Fuzz(func(t *testing.T, family, kind, input string) {
		if len(input) > 8<<20 {
			t.Skip()
		}
		var version DNFVersion
		switch family {
		case "5.2":
			version = DNFVersion{Major: 5, Minor: 2, DNF5: true}
		case "5.3":
			version = DNFVersion{Major: 5, Minor: 3, DNF5: true}
		default:
			return
		}
		switch kind {
		case "list.json":
			_, _ = parseDNF5AdvisoryList([]byte(input), version)
		case "info.json":
			_, _ = parseDNF5AdvisoryInfo([]byte(input), version)
		}
	})
}
