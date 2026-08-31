package apt

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestParseInstalledPackagesFixtures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		directory string
		count     int
	}{
		{directory: "debian12", count: 1},
		{directory: "debian13", count: 1},
		{directory: "ubuntu2204", count: 1},
		{directory: "ubuntu2404", count: 2},
		{directory: "ubuntu2604", count: 1},
	}

	for _, test := range tests {
		test := test
		t.Run(test.directory, func(t *testing.T) {
			t.Parallel()

			data := readAPTFixture(t, test.directory, "dpkg-query.txt")
			packages, err := ParseInstalledPackages(data)
			if err != nil {
				t.Fatalf("parse installed packages: %v", err)
			}
			if len(packages) != test.count {
				t.Fatalf("packages = %d, want %d", len(packages), test.count)
			}
			for _, pkg := range packages {
				if pkg.Name == "" || pkg.Architecture == "" || pkg.Version.Full == "" {
					t.Errorf("incomplete package: %#v", pkg)
				}
			}

			again, err := ParseInstalledPackages(data)
			if err != nil {
				t.Fatalf("parse installed packages again: %v", err)
			}
			if !reflect.DeepEqual(packages, again) {
				t.Error("installed-package parsing is not deterministic")
			}
		})
	}
}

func TestParseInstalledPackagesPreservesDebianVersion(t *testing.T) {
	t.Parallel()

	data := []byte("native-pkg:amd64|amd64|1.2.3~rc1|installed\n" +
		"revision-pkg:amd64|amd64|3.5.6-1~deb13u2|installed\n" +
		"epoch-pkg:amd64|amd64|2:4.0.4-4ubuntu3.2|installed\n")
	packages, err := ParseInstalledPackages(data)
	if err != nil {
		t.Fatalf("parse installed packages: %v", err)
	}

	want := []InstalledPackage{
		{
			Name: "epoch-pkg", Architecture: "amd64",
			Version: DebianVersion{Full: "2:4.0.4-4ubuntu3.2", Epoch: "2", Version: "4.0.4", Release: "4ubuntu3.2"},
		},
		{
			Name: "native-pkg", Architecture: "amd64",
			Version: DebianVersion{Full: "1.2.3~rc1", Version: "1.2.3~rc1"},
		},
		{
			Name: "revision-pkg", Architecture: "amd64",
			Version: DebianVersion{Full: "3.5.6-1~deb13u2", Version: "3.5.6", Release: "1~deb13u2"},
		},
	}
	if !reflect.DeepEqual(packages, want) {
		t.Fatalf("packages:\ngot:  %#v\nwant: %#v", packages, want)
	}
}

func TestParseInstalledPackagesFiltersResidualStates(t *testing.T) {
	t.Parallel()

	data := []byte("old-pkg:amd64|amd64||config-files\n" +
		"half-pkg:amd64|amd64|1.0-1|half-configured\n" +
		"live-pkg:amd64|amd64|1.0-1|installed\n")
	packages, err := ParseInstalledPackages(data)
	if err != nil {
		t.Fatalf("parse installed packages: %v", err)
	}
	if len(packages) != 1 || packages[0].Name != "live-pkg" {
		t.Fatalf("packages = %#v, want only live-pkg", packages)
	}
}

func TestParseInstalledPackagesMultiarchAndAll(t *testing.T) {
	t.Parallel()

	data := []byte("libmulti:amd64|amd64|1.0-1|installed\n" +
		"libmulti:i386|i386|1.0-1|installed\n" +
		"data-pkg|all|2.0-1|installed\n")
	packages, err := ParseInstalledPackages(data)
	if err != nil {
		t.Fatalf("parse installed packages: %v", err)
	}
	if len(packages) != 3 {
		t.Fatalf("packages = %d, want 3", len(packages))
	}
	if packages[0].Name != "data-pkg" || packages[0].Architecture != "all" ||
		packages[1].Architecture != "amd64" || packages[2].Architecture != "i386" {
		t.Fatalf("unexpected multiarch ordering: %#v", packages)
	}
}

func TestParseInstalledPackagesRejectsMalformedRows(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "field count", input: "pkg|amd64|1.0\n", want: "expected four fields"},
		{name: "invalid name", input: "Bad:amd64|amd64|1.0|installed\n", want: "invalid binary package name"},
		{name: "architecture mismatch", input: "pkg:arm64|amd64|1.0|installed\n", want: "does not match"},
		{name: "invalid architecture", input: "pkg:AMD64|AMD64|1.0|installed\n", want: "invalid package architecture"},
		{name: "unknown status", input: "pkg:amd64|amd64|1.0|held\n", want: "unknown package status"},
		{name: "invalid version", input: "pkg:amd64|amd64|epoch:1.0|installed\n", want: "invalid Debian version epoch"},
		{
			name:  "duplicate",
			input: "pkg:amd64|amd64|1.0|installed\npkg:amd64|amd64|1.0|installed\n",
			want:  "duplicate installed package",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseInstalledPackages([]byte(test.input))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestParseDebianVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		full string
		want DebianVersion
	}{
		{full: "1.0", want: DebianVersion{Full: "1.0", Version: "1.0"}},
		{full: "1.0-beta-2", want: DebianVersion{Full: "1.0-beta-2", Version: "1.0-beta", Release: "2"}},
		{
			full: "12:3.5.6-1~deb13u2",
			want: DebianVersion{Full: "12:3.5.6-1~deb13u2", Epoch: "12", Version: "3.5.6", Release: "1~deb13u2"},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.full, func(t *testing.T) {
			t.Parallel()

			got, err := ParseDebianVersion(test.full)
			if err != nil {
				t.Fatalf("ParseDebianVersion: %v", err)
			}
			if got != test.want {
				t.Errorf("version = %#v, want %#v", got, test.want)
			}
		})
	}
}

func TestParseDebianVersionRejectsMalformedValues(t *testing.T) {
	t.Parallel()

	for _, value := range []string{"", "x.0", ":1.0", "x:1.0", "1.0-", "1.0=2", "1.0 2"} {
		value := value
		t.Run(value, func(t *testing.T) {
			t.Parallel()
			if _, err := ParseDebianVersion(value); err == nil {
				t.Fatalf("ParseDebianVersion(%q) succeeded", value)
			}
		})
	}
}

func TestBatchPolicyArgumentsBounds(t *testing.T) {
	t.Parallel()

	packages := make([]InstalledPackage, 0, 700)
	for index := range 700 {
		packages = append(packages, InstalledPackage{
			Name:         fmt.Sprintf("package-%03d-%s", index, strings.Repeat("x", 116)),
			Architecture: "amd64",
		})
	}
	batches, err := BatchPolicyArguments(packages)
	if err != nil {
		t.Fatalf("batch policy arguments: %v", err)
	}
	if len(batches) < 2 {
		t.Fatalf("batches = %d, want multiple count/byte-bounded batches", len(batches))
	}

	total := 0
	for batchIndex, batch := range batches {
		if len(batch) == 0 || len(batch) > maxPolicyPackageArguments {
			t.Errorf("batch %d has %d arguments", batchIndex, len(batch))
		}
		bytes := 0
		for _, argument := range batch {
			bytes += len(argument) + 1
		}
		if bytes > maxPolicyArgumentBytes {
			t.Errorf("batch %d has %d encoded argument bytes", batchIndex, bytes)
		}
		total += len(batch)
	}
	if total != len(packages) {
		t.Errorf("batched packages = %d, want %d", total, len(packages))
	}
}

func TestBatchPolicyArgumentsPackageCountBoundary(t *testing.T) {
	t.Parallel()

	packages := make([]InstalledPackage, 513)
	for index := range packages {
		packages[index] = InstalledPackage{
			Name:         fmt.Sprintf("pkg-%03d", index),
			Architecture: "amd64",
		}
	}
	batches, err := BatchPolicyArguments(packages)
	if err != nil {
		t.Fatalf("batch policy arguments: %v", err)
	}
	if len(batches) != 2 {
		t.Fatalf("batches = %d, want 2", len(batches))
	}
	if len(batches[0]) != 512 || len(batches[1]) != 1 {
		t.Fatalf("batch sizes = %v, want [512 1]", []int{len(batches[0]), len(batches[1])})
	}
}

func TestBatchPolicyArgumentsRejectsDuplicatesAndOversize(t *testing.T) {
	t.Parallel()

	pkg := InstalledPackage{Name: "package", Architecture: "amd64"}
	if _, err := BatchPolicyArguments([]InstalledPackage{pkg, pkg}); err == nil {
		t.Error("duplicate package was accepted")
	}
	if _, err := BatchPolicyArguments([]InstalledPackage{{
		Name: strings.Repeat("a", maxPolicyArgumentBytes), Architecture: "amd64",
	}}); err == nil {
		t.Error("oversize argument was accepted")
	}

	empty, err := BatchPolicyArguments(nil)
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty batches = %#v, %v; want non-nil empty result", empty, err)
	}
}
