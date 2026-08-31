package apt

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseRepositoryIndexesFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		directory           string
		repositoryCount     int
		securityTargetCount int
	}{
		{directory: "debian12", repositoryCount: 2, securityTargetCount: 1},
		{directory: "debian13", repositoryCount: 2, securityTargetCount: 1},
		{directory: "ubuntu2204", repositoryCount: 3, securityTargetCount: 1},
		{directory: "ubuntu2404", repositoryCount: 3, securityTargetCount: 1},
		{directory: "ubuntu2604", repositoryCount: 3, securityTargetCount: 1},
	}

	for _, test := range tests {
		test := test
		t.Run(test.directory, func(t *testing.T) {
			t.Parallel()

			data := readAPTFixture(t, test.directory, "indextargets.txt")
			indexes, err := ParseRepositoryIndexes(data)
			if err != nil {
				t.Fatalf("parse repository indexes: %v", err)
			}
			if len(indexes.Repositories) != test.repositoryCount {
				t.Fatalf("repositories = %d, want %d", len(indexes.Repositories), test.repositoryCount)
			}
			if len(indexes.Targets) != test.repositoryCount {
				t.Fatalf("targets = %d, want %d", len(indexes.Targets), test.repositoryCount)
			}

			securityTargets := 0
			for _, target := range indexes.Targets {
				if target.Security {
					securityTargets++
				}
			}
			if securityTargets != test.securityTargetCount {
				t.Errorf("security targets = %d, want %d", securityTargets, test.securityTargetCount)
			}

			for _, repository := range indexes.Repositories {
				if len(repository.ID) != len("apt-")+32 || !strings.HasPrefix(repository.ID, "apt-") {
					t.Errorf("repository ID %q is not a truncated SHA-256 ID", repository.ID)
				}
				if repository.Name == "" {
					t.Error("repository name is empty")
				}
			}

			again, err := ParseRepositoryIndexes(data)
			if err != nil {
				t.Fatalf("parse repository indexes again: %v", err)
			}
			if !reflect.DeepEqual(indexes, again) {
				t.Error("repository parsing is not deterministic")
			}
		})
	}
}

func TestParseRepositoryIndexesAcceptsArbitraryFieldOrder(t *testing.T) {
	t.Parallel()

	data := readAPTFixture(t, "ubuntu2404", "indextargets.txt")
	want, err := ParseRepositoryIndexes(data)
	if err != nil {
		t.Fatalf("parse ordered fixture: %v", err)
	}

	records := strings.Split(strings.TrimSpace(string(data)), "\n\n")
	for recordIndex, record := range records {
		lines := strings.Split(record, "\n")
		for left, right := 0, len(lines)-1; left < right; left, right = left+1, right-1 {
			lines[left], lines[right] = lines[right], lines[left]
		}
		records[recordIndex] = strings.Join(lines, "\n")
	}

	got, err := ParseRepositoryIndexes([]byte(strings.Join(records, "\n\n") + "\n"))
	if err != nil {
		t.Fatalf("parse reordered fixture: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reordered parse differs:\ngot:  %#v\nwant: %#v", got, want)
	}
}

func TestParseRepositoryIndexesFiltersNonBinaryAndDisabledTargets(t *testing.T) {
	t.Parallel()

	binary := aptTargetRecord(targetRecordOptions{})
	source := strings.ReplaceAll(binary, "Identifier: Packages", "Identifier: Sources")
	translation := strings.ReplaceAll(binary, "Created-By: Packages", "Created-By: Translations")
	disabled := strings.ReplaceAll(binary, "DefaultEnabled: yes", "DefaultEnabled: no")

	indexes, err := ParseRepositoryIndexes([]byte(source + translation + disabled + binary))
	if err != nil {
		t.Fatalf("parse repository indexes: %v", err)
	}
	if len(indexes.Repositories) != 1 || len(indexes.Targets) != 1 {
		t.Fatalf("parsed repositories/targets = %d/%d, want 1/1", len(indexes.Repositories), len(indexes.Targets))
	}
}

func TestParseRepositoryIndexesRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "missing separator", input: "Origin Debian\n", want: "missing field separator"},
		{name: "orphan continuation", input: " continued\n", want: "orphan continuation"},
		{name: "duplicate field", input: "Origin: Debian\norigin: Other\n", want: "duplicate field"},
		{name: "invalid field name", input: "Bad_Name: value\n", want: "invalid field name"},
		{
			name:  "missing required filename",
			input: strings.ReplaceAll(aptTargetRecord(targetRecordOptions{}), "Filename: /var/lib/apt/lists/example_Packages\n", ""),
			want:  "required field Filename is empty",
		},
		{
			name:  "invalid enabled flag",
			input: strings.ReplaceAll(aptTargetRecord(targetRecordOptions{}), "DefaultEnabled: yes", "DefaultEnabled: true"),
			want:  "field defaultenabled must be yes or no",
		},
		{
			name:  "relative filename",
			input: strings.ReplaceAll(aptTargetRecord(targetRecordOptions{}), "/var/lib/apt/lists/example_Packages", "relative/index"),
			want:  "Filename must be an absolute path",
		},
		{
			name:  "multiline suite",
			input: strings.ReplaceAll(aptTargetRecord(targetRecordOptions{}), "Suite: stable\n", "Suite: stable\n continued\n"),
			want:  "field Suite must be a single line",
		},
		{
			name:  "invalid URI",
			input: strings.ReplaceAll(aptTargetRecord(targetRecordOptions{}), "URI: https://packages.example/", "URI: https://packages.example/%zz"),
			want:  "invalid uri repository URL",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseRepositoryIndexes([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseRepositoryIndexesGroupsReleaseAcrossMirrorsAndComponents(t *testing.T) {
	t.Parallel()

	first := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://mirror-one.example/debian",
		component:      "main",
		filename:       "/var/lib/apt/lists/mirror-one_Packages",
	})
	second := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://mirror-two.example/debian",
		component:      "contrib",
		filename:       "/var/lib/apt/lists/mirror-two_Packages",
	})

	indexes, err := ParseRepositoryIndexes([]byte(first + second))
	if err != nil {
		t.Fatalf("parse repository indexes: %v", err)
	}
	if len(indexes.Repositories) != 1 || len(indexes.Targets) != 2 {
		t.Fatalf("parsed repositories/targets = %d/%d, want 1/2", len(indexes.Repositories), len(indexes.Targets))
	}
	if indexes.Targets[0].RepositoryID != indexes.Targets[1].RepositoryID {
		t.Error("mirror targets did not map to one logical Release repository")
	}
	if got, want := indexes.Repositories[0].Name, "Debian (stable) [contrib, main]"; got != want {
		t.Errorf("repository name = %q, want %q", got, want)
	}
}

func TestParseRepositoryIndexesDetectsIDCollisions(t *testing.T) {
	t.Parallel()

	parser := newRepositoryParserForTest(func(string) string { return "apt-collision" })
	first := aptTargetRecord(targetRecordOptions{suite: "stable", codename: "trixie"})
	second := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://security.example/debian",
		filename:       "/var/lib/apt/lists/security_Packages",
		label:          "Debian-Security",
		suite:          "stable-security",
		codename:       "trixie-security",
	})

	_, err := parser.Parse([]byte(first + second))
	if err == nil || !strings.Contains(err.Error(), "APT repository ID collision") {
		t.Fatalf("error = %v, want collision", err)
	}
}

func TestParseRepositoryIndexesRedactsCredentials(t *testing.T) {
	t.Parallel()

	withCredentials := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://alice:s3cr3t@packages.example/debian",
		repositoryURL:  "https://alice:s3cr3t@packages.example/debian/",
		omitLabel:      true,
	})
	withoutCredentials := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://packages.example/debian",
		repositoryURL:  "https://packages.example/debian/",
		omitLabel:      true,
	})

	got, err := ParseRepositoryIndexes([]byte(withCredentials))
	if err != nil {
		t.Fatalf("parse credentialed repository: %v", err)
	}
	want, err := ParseRepositoryIndexes([]byte(withoutCredentials))
	if err != nil {
		t.Fatalf("parse uncredentialed repository: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("credentials affected normalized result:\ngot:  %#v\nwant: %#v", got, want)
	}

	serialized := fmt.Sprintf("%#v", got)
	for _, secret := range []string{"alice", "s3cr3t"} {
		if strings.Contains(serialized, secret) {
			t.Errorf("normalized values contain credential %q", secret)
		}
	}

	malformed := strings.ReplaceAll(withCredentials, "URI: https://alice:s3cr3t@packages.example/debian/", "URI: https://alice:s3cr3t@packages.example/%zz")
	_, err = ParseRepositoryIndexes([]byte(malformed))
	if err == nil {
		t.Fatal("malformed credentialed URL was accepted")
	}
	for _, secret := range []string{"alice", "s3cr3t", "%zz"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error contains credential or raw URL fragment %q: %v", secret, err)
		}
	}
}

func TestSecurityRepositoryRules(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		options  targetRecordOptions
		security bool
	}{
		{
			name: "Debian security",
			options: targetRecordOptions{
				origin: "Debian", label: "Debian-Security", suite: "stable-security", codename: "trixie-security",
			},
			security: true,
		},
		{
			name: "untrusted Debian security",
			options: targetRecordOptions{
				origin: "Debian", label: "Debian-Security", suite: "stable-security", codename: "trixie-security", trusted: "no",
			},
		},
		{
			name: "Ubuntu security",
			options: targetRecordOptions{
				origin: "Ubuntu", label: "Ubuntu", suite: "noble-security", codename: "noble",
			},
			security: true,
		},
		{
			name: "Ubuntu updates",
			options: targetRecordOptions{
				origin: "Ubuntu", label: "Ubuntu", suite: "noble-updates", codename: "noble",
			},
		},
		{
			name: "spoofed security suffix",
			options: targetRecordOptions{
				origin: "Example", label: "Ubuntu", suite: "noble-security", codename: "noble",
			},
		},
		{
			name: "ESM Apps security",
			options: targetRecordOptions{
				origin: "UbuntuESMApps", label: "UbuntuESMApps", suite: "jammy-apps-security", codename: "jammy",
			},
			security: true,
		},
		{
			name: "ESM Infra security",
			options: targetRecordOptions{
				origin: "UbuntuESM", label: "UbuntuESM", suite: "jammy-infra-security", codename: "jammy",
			},
			security: true,
		},
		{
			name: "lookalike ESM origin",
			options: targetRecordOptions{
				origin: "UbuntuESMInfra", label: "UbuntuESM", suite: "jammy-infra-security", codename: "jammy",
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			indexes, err := ParseRepositoryIndexes([]byte(aptTargetRecord(test.options)))
			if err != nil {
				t.Fatalf("parse target: %v", err)
			}
			if got := indexes.Targets[0].Security; got != test.security {
				t.Errorf("Security = %t, want %t", got, test.security)
			}
		})
	}
}

type targetRecordOptions struct {
	descriptionURL string
	repositoryURL  string
	filename       string
	component      string
	origin         string
	label          string
	omitLabel      bool
	suite          string
	codename       string
	trusted        string
}

func aptTargetRecord(options targetRecordOptions) string {
	if options.descriptionURL == "" {
		options.descriptionURL = "https://packages.example/debian"
	}
	if options.repositoryURL == "" {
		options.repositoryURL = options.descriptionURL + "/"
	}
	if options.filename == "" {
		options.filename = "/var/lib/apt/lists/example_Packages"
	}
	if options.component == "" {
		options.component = "main"
	}
	if options.origin == "" {
		options.origin = "Debian"
	}
	if options.label == "" && !options.omitLabel {
		options.label = "Debian"
	}
	if options.suite == "" {
		options.suite = "stable"
	}
	if options.codename == "" {
		options.codename = "trixie"
	}
	if options.trusted == "" {
		options.trusted = "yes"
	}

	return fmt.Sprintf(`Identifier: Packages
Created-By: Packages
Target-Of: deb
DefaultEnabled: yes
Trusted: %s
Description: %s %s/%s amd64 Packages
URI: %s
Base-URI: %s
Repo-URI: %s
Site: %s
Filename: %s
Architecture: amd64
Component: %s
Origin: %s
Label: %s
Suite: %s
Codename: %s

`, options.trusted, options.descriptionURL, options.codename, options.component,
		options.repositoryURL, options.repositoryURL, options.repositoryURL,
		strings.TrimRight(options.repositoryURL, "/"), options.filename, options.component,
		options.origin, options.label, options.suite, options.codename)
}

func readAPTFixture(t *testing.T, directory, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", directory, name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	return data
}
