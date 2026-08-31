package apt

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var targetFixtureDirectories = []string{
	"debian12",
	"debian13",
	"ubuntu2204",
	"ubuntu2404",
	"ubuntu2604",
}

func TestTargetFormatFixtures(t *testing.T) {
	t.Parallel()

	for _, directory := range targetFixtureDirectories {
		directory := directory
		t.Run(directory, func(t *testing.T) {
			t.Parallel()

			for _, name := range []string{"indextargets.txt", "dpkg-query.txt", "policy.txt"} {
				data, err := os.ReadFile(filepath.Join("testdata", directory, name))
				if err != nil {
					t.Fatalf("read %s: %v", name, err)
				}
				if len(strings.TrimSpace(string(data))) == 0 {
					t.Fatalf("%s is empty", name)
				}
			}
		})
	}
}

func TestEveryPolicySourceMapsToCapturedIndexTarget(t *testing.T) {
	t.Parallel()

	for _, directory := range targetFixtureDirectories {
		directory := directory
		t.Run(directory, func(t *testing.T) {
			t.Parallel()

			indexData, err := os.ReadFile(filepath.Join("testdata", directory, "indextargets.txt"))
			if err != nil {
				t.Fatalf("read index targets: %v", err)
			}
			indexes, err := ParseRepositoryIndexes(indexData)
			if err != nil {
				t.Fatalf("parse index targets: %v", err)
			}
			targets := make(map[string]struct{}, len(indexes.Targets))
			for _, target := range indexes.Targets {
				targets[target.Source] = struct{}{}
			}

			policyData, err := os.ReadFile(filepath.Join("testdata", directory, "policy.txt"))
			if err != nil {
				t.Fatalf("read policy: %v", err)
			}
			for _, line := range strings.Split(string(policyData), "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 || !strings.HasPrefix(fields[1], "http") {
					continue
				}

				source := strings.Join(fields[1:], " ")
				if _, ok := targets[source]; !ok {
					t.Errorf("policy source %q has no captured index target", source)
				}
			}
		})
	}
}

func FuzzDeb822Contract(f *testing.F) {
	for _, directory := range targetFixtureDirectories {
		data, err := os.ReadFile(filepath.Join("testdata", directory, "indextargets.txt"))
		if err != nil {
			f.Fatalf("read seed: %v", err)
		}
		f.Add(string(data))
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8<<20 {
			t.Skip()
		}
		_, _ = ParseRepositoryIndexes([]byte(input))
	})
}

func FuzzPolicyContract(f *testing.F) {
	for _, directory := range targetFixtureDirectories {
		data, err := os.ReadFile(filepath.Join("testdata", directory, "policy.txt"))
		if err != nil {
			f.Fatalf("read seed: %v", err)
		}
		f.Add(string(data))
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8<<20 {
			t.Skip()
		}
		_, _ = parsePolicyBlocks([]byte(input))
	})
}

func FuzzInstalledContract(f *testing.F) {
	for _, directory := range targetFixtureDirectories {
		data, err := os.ReadFile(filepath.Join("testdata", directory, "dpkg-query.txt"))
		if err != nil {
			f.Fatalf("read seed: %v", err)
		}
		f.Add(string(data))
	}

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 8<<20 {
			t.Skip()
		}
		_, _ = ParseInstalledPackages([]byte(input))
	})
}
