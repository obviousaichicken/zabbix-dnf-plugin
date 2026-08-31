package apt

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParsePackagePoliciesFixtures(t *testing.T) {
	t.Parallel()

	for _, directory := range targetFixtureDirectories {
		directory := directory
		t.Run(directory, func(t *testing.T) {
			t.Parallel()

			installed, err := ParseInstalledPackages(readAPTFixture(t, directory, "dpkg-query.txt"))
			if err != nil {
				t.Fatalf("parse installed packages: %v", err)
			}
			indexes, err := ParseRepositoryIndexes(readAPTFixture(t, directory, "indextargets.txt"))
			if err != nil {
				t.Fatalf("parse repository indexes: %v", err)
			}
			data := readAPTFixture(t, directory, "policy.txt")
			policies, err := ParsePackagePolicies(data, installed, indexes)
			if err != nil {
				t.Fatalf("parse package policies: %v", err)
			}
			if len(policies) != len(installed) {
				t.Fatalf("policies = %d, want %d", len(policies), len(installed))
			}
			for _, policy := range policies {
				if policy.Installed == nil || policy.Candidate == nil {
					t.Errorf("policy has missing versions: %#v", policy)
				}
				if len(policy.CandidateSources) == 0 {
					t.Errorf("policy has no exact-candidate sources: %#v", policy)
				}
				for _, source := range policy.CandidateSources {
					if source.RepositoryID == "" || source.Source == "" {
						t.Errorf("incomplete candidate source: %#v", source)
					}
				}
			}

			again, err := ParsePackagePolicies(data, installed, indexes)
			if err != nil {
				t.Fatalf("parse package policies again: %v", err)
			}
			if !reflect.DeepEqual(policies, again) {
				t.Error("policy parsing is not deterministic")
			}
		})
	}
}

func TestParsePackagePoliciesPinningPhasingAndHeldPackage(t *testing.T) {
	t.Parallel()

	indexes := mustPolicyIndexes(t, aptTargetRecord(targetRecordOptions{}))
	requested := []InstalledPackage{{
		Name: "held-pkg", Architecture: "amd64", Version: mustDebianVersion(t, "1.0-1"),
	}}
	data := []byte(`held-pkg:
  Installed: 1.0-1
  Candidate: 2.0~rc1-1
  Version table:
     2.0~rc1-1 1001 (phased 20%)
        1001 https://packages.example/debian trixie/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
     0.9-1 -1
        -1 https://unknown.example/debian trixie/main amd64 Packages
`)

	policies, err := ParsePackagePolicies(data, requested, indexes)
	if err != nil {
		t.Fatalf("parse package policy: %v", err)
	}
	policy := policies[0]
	if policy.Candidate == nil || policy.Candidate.Full != "2.0~rc1-1" {
		t.Fatalf("Candidate = %#v, want 2.0~rc1-1", policy.Candidate)
	}
	if policy.CandidatePriority != 1001 || policy.CandidatePhasedPercentage == nil ||
		*policy.CandidatePhasedPercentage != 20 {
		t.Errorf("candidate priority/phasing = %d/%v, want 1001/20", policy.CandidatePriority, policy.CandidatePhasedPercentage)
	}
	if len(policy.CandidateSources) != 1 || policy.CandidateSources[0].Priority != 1001 {
		t.Errorf("candidate sources = %#v", policy.CandidateSources)
	}
}

func TestParsePackagePoliciesMultiarch(t *testing.T) {
	t.Parallel()

	amd64Target := aptTargetRecord(targetRecordOptions{})
	i386Target := strings.ReplaceAll(amd64Target, "amd64", "i386")
	indexes := mustPolicyIndexes(t, amd64Target+i386Target)
	requested := []InstalledPackage{
		{Name: "libmulti", Architecture: "amd64", Version: mustDebianVersion(t, "1.0-1")},
		{Name: "libmulti", Architecture: "i386", Version: mustDebianVersion(t, "1.0-1")},
	}
	data := []byte(`libmulti:amd64:
  Installed: 1.0-1
  Candidate: 1.1-1
  Version table:
     1.1-1 500
        500 https://packages.example/debian trixie/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
libmulti:i386:
  Installed: 1.0-1
  Candidate: 1.1-1
  Version table:
     1.1-1 500
        500 https://packages.example/debian trixie/main i386 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`)

	policies, err := ParsePackagePolicies(data, requested, indexes)
	if err != nil {
		t.Fatalf("parse multiarch policies: %v", err)
	}
	if len(policies) != 2 || policies[0].Architecture != "amd64" || policies[1].Architecture != "i386" {
		t.Fatalf("policies = %#v", policies)
	}
}

func TestParsePackagePoliciesArchitectureAll(t *testing.T) {
	t.Parallel()

	target := strings.ReplaceAll(aptTargetRecord(targetRecordOptions{}), "amd64", "all")
	indexes := mustPolicyIndexes(t, target)
	requested := []InstalledPackage{{
		Name: "data-pkg", Architecture: "all", Version: mustDebianVersion(t, "1.0-1"),
	}}
	data := []byte(`data-pkg:
  Installed: 1.0-1
  Candidate: 1.1-1
  Version table:
     1.1-1 500
        500 https://packages.example/debian trixie/main all Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`)

	policies, err := ParsePackagePolicies(data, requested, indexes)
	if err != nil {
		t.Fatalf("parse architecture-all policy: %v", err)
	}
	if policies[0].Architecture != "all" || len(policies[0].CandidateSources) != 1 {
		t.Fatalf("policy = %#v", policies[0])
	}
}

func TestParsePackagePoliciesLocalAndAbsentCandidates(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		data string
	}{
		{
			name: "local installed package",
			data: `local-pkg:
  Installed: 1.0-1
  Candidate: 1.0-1
  Version table:
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`,
		},
		{
			name: "no candidate",
			data: `local-pkg:
  Installed: 1.0-1
  Candidate: (none)
  Version table:
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			requested := []InstalledPackage{{
				Name: "local-pkg", Architecture: "amd64", Version: mustDebianVersion(t, "1.0-1"),
			}}
			policies, err := ParsePackagePolicies([]byte(test.data), requested, RepositoryIndexes{})
			if err != nil {
				t.Fatalf("parse local package policy: %v", err)
			}
			if len(policies[0].CandidateSources) != 0 {
				t.Errorf("local candidate sources = %#v, want empty", policies[0].CandidateSources)
			}
		})
	}
}

func TestParsePackagePoliciesPreservesCandidateSourceOrderAndPriorities(t *testing.T) {
	t.Parallel()

	first := aptTargetRecord(targetRecordOptions{descriptionURL: "https://first.example/debian"})
	second := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://second.example/debian",
		filename:       "/var/lib/apt/lists/second_Packages",
	})
	indexes := mustPolicyIndexes(t, first+second)
	requested := []InstalledPackage{{
		Name: "order-pkg", Architecture: "amd64", Version: mustDebianVersion(t, "1.0-1"),
	}}
	data := []byte(`order-pkg:
  Installed: 1.0-1
  Candidate: 2.0-1
  Version table:
     2.0-1 700
        600 https://first.example/debian trixie/main amd64 Packages
        700 https://second.example/debian trixie/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`)

	policies, err := ParsePackagePolicies(data, requested, indexes)
	if err != nil {
		t.Fatalf("parse ordered sources: %v", err)
	}
	sources := policies[0].CandidateSources
	if len(sources) != 2 || sources[0].Priority != 600 || sources[1].Priority != 700 ||
		!strings.Contains(sources[0].Source, "first.example") ||
		!strings.Contains(sources[1].Source, "second.example") {
		t.Fatalf("candidate sources lost order or priority: %#v", sources)
	}
}

func TestParsePackagePoliciesFailsClosedOnCandidateSourceMismatch(t *testing.T) {
	t.Parallel()

	indexes := mustPolicyIndexes(t, aptTargetRecord(targetRecordOptions{}))
	requested := []InstalledPackage{{
		Name: "secure-pkg", Architecture: "amd64", Version: mustDebianVersion(t, "1.0-1"),
	}}
	data := []byte(`secure-pkg:
  Installed: 1.0-1
  Candidate: 2.0-1
  Version table:
     2.0-1 500
        500 https://alice:s3cr3t@unknown.example/debian trixie/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`)

	_, err := ParsePackagePolicies(data, requested, indexes)
	if err == nil || !strings.Contains(err.Error(), "no matching APT index target") {
		t.Fatalf("error = %v, want fail-closed source mismatch", err)
	}
	for _, secret := range []string{"alice", "s3cr3t", "unknown.example"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("source mismatch error contains repository detail %q: %v", secret, err)
		}
	}
}

func TestParsePackagePoliciesRedactsMatchingSourceCredentials(t *testing.T) {
	t.Parallel()

	target := aptTargetRecord(targetRecordOptions{
		descriptionURL: "https://index-user:index-secret@packages.example/debian",
		repositoryURL:  "https://index-user:index-secret@packages.example/debian/",
	})
	indexes := mustPolicyIndexes(t, target)
	requested := []InstalledPackage{{
		Name: "secure-pkg", Architecture: "amd64", Version: mustDebianVersion(t, "1.0-1"),
	}}
	data := []byte(`secure-pkg:
  Installed: 1.0-1
  Candidate: 2.0-1
  Version table:
     2.0-1 500
        500 https://policy-user:policy-secret@packages.example/debian trixie/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`)

	policies, err := ParsePackagePolicies(data, requested, indexes)
	if err != nil {
		t.Fatalf("parse credentialed policy source: %v", err)
	}
	serialized := fmt.Sprintf("%#v %#v", indexes, policies)
	for _, secret := range []string{"index-user", "index-secret", "policy-user", "policy-secret"} {
		if strings.Contains(serialized, secret) {
			t.Errorf("parsed values contain credential %q", secret)
		}
	}
}

func TestParsePackagePoliciesRejectsMalformedStructure(t *testing.T) {
	t.Parallel()

	base := `pkg:
  Installed: 1.0-1
  Candidate: 2.0-1
  Version table:
     2.0-1 500
        500 https://packages.example/debian trixie/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "content before header", data: "  Installed: 1.0-1\n", want: "content before package header"},
		{name: "header terminator", data: strings.Replace(base, "pkg:\n", "pkg\n", 1), want: "missing trailing colon"},
		{name: "missing property", data: strings.Replace(base, "  Candidate: 2.0-1\n", "", 1), want: "misplaced or duplicate Version table"},
		{name: "duplicate property", data: strings.Replace(base, "  Candidate: 2.0-1\n", "  Candidate: 2.0-1\n  Candidate: 2.0-1\n", 1), want: "duplicate Candidate"},
		{name: "source before version", data: strings.Replace(base, "     2.0-1 500\n", "", 1), want: "source precedes version"},
		{name: "invalid priority", data: strings.Replace(base, "2.0-1 500", "2.0-1 high", 1), want: "invalid policy priority"},
		{name: "invalid phasing", data: strings.Replace(base, "2.0-1 500", "2.0-1 500 (phased 101%)", 1), want: "invalid phased-update percentage"},
		{name: "tabs", data: strings.Replace(base, "     2.0-1", "\t2.0-1", 1), want: "tabs are not permitted"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := parsePolicyBlocks([]byte(test.data))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParsePackagePoliciesRejectsSemanticMismatches(t *testing.T) {
	t.Parallel()

	indexes := mustPolicyIndexes(t, aptTargetRecord(targetRecordOptions{}))
	requested := []InstalledPackage{{
		Name: "pkg", Architecture: "amd64", Version: mustDebianVersion(t, "1.0-1"),
	}}
	base := `pkg:
  Installed: 1.0-1
  Candidate: 2.0-1
  Version table:
     2.0-1 500
        500 https://packages.example/debian trixie/main amd64 Packages
 *** 1.0-1 100
        100 /var/lib/dpkg/status
`
	tests := []struct {
		name string
		data string
		want string
	}{
		{name: "candidate absent from table", data: strings.Replace(base, "Candidate: 2.0-1", "Candidate: 3.0-1", 1), want: "no exact version-table entry"},
		{name: "installed marker mismatch", data: strings.Replace(base, "*** 1.0-1", "*** 2.0-1", 1), want: "duplicate version-table version"},
		{name: "missing returned block", data: "", want: "returned 0 package blocks"},
		{name: "extra returned block", data: base + base, want: "returned 2 package blocks"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParsePackagePolicies([]byte(test.data), requested, indexes)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParsePackagePoliciesRejectsAmbiguousUnqualifiedMultiarchHeader(t *testing.T) {
	t.Parallel()

	requested := []InstalledPackage{
		{Name: "libmulti", Architecture: "amd64"},
		{Name: "libmulti", Architecture: "i386"},
	}
	data := []byte(`libmulti:
  Installed: (none)
  Candidate: (none)
  Version table:
libmulti:i386:
  Installed: (none)
  Candidate: (none)
  Version table:
`)
	_, err := ParsePackagePolicies(data, requested, RepositoryIndexes{})
	if err == nil || !strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("error = %v, want ambiguous header", err)
	}
}

func mustPolicyIndexes(t *testing.T, records string) RepositoryIndexes {
	t.Helper()

	indexes, err := ParseRepositoryIndexes([]byte(records))
	if err != nil {
		t.Fatalf("parse policy indexes: %v", err)
	}

	return indexes
}

func mustDebianVersion(t *testing.T, value string) DebianVersion {
	t.Helper()

	version, err := ParseDebianVersion(value)
	if err != nil {
		t.Fatalf("parse Debian version %q: %v", value, err)
	}

	return version
}
