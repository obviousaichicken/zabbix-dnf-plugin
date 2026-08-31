package results_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/results"
)

func TestBuildPackagesDNFGolden(t *testing.T) {
	t.Parallel()

	snapshot := dnfSnapshot()
	payload, err := results.BuildPackages(snapshot)
	if err != nil {
		t.Fatalf("BuildPackages() error = %v", err)
	}
	payload.Collection.DurationMS = 0

	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	want, err := os.ReadFile("testdata/packages-dnf.golden.json")
	if err != nil {
		t.Fatalf("read golden payload: %v", err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("packages.get payload changed\ngot:  %s\nwant: %s", got, want)
	}
}

func TestBuildPackagesAPTGolden(t *testing.T) {
	t.Parallel()

	snapshot := aptSnapshot()
	payload, err := results.BuildPackages(snapshot)
	if err != nil {
		t.Fatalf("BuildPackages() error = %v", err)
	}
	payload.Collection.DurationMS = 0

	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	want, err := os.ReadFile("testdata/packages-apt.golden.json")
	if err != nil {
		t.Fatalf("read golden payload: %v", err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))
	if !bytes.Equal(got, want) {
		t.Fatalf("APT packages.get payload changed\ngot:  %s\nwant: %s", got, want)
	}
}

func TestBuildPackagesPreservesDNFLegacyFacts(t *testing.T) {
	t.Parallel()

	snapshot := dnfSnapshot()
	legacy, err := results.BuildLegacy(snapshot.Repositories, snapshot.Updates)
	if err != nil {
		t.Fatalf("BuildLegacy() error = %v", err)
	}
	generic, err := results.BuildPackages(snapshot)
	if err != nil {
		t.Fatalf("BuildPackages() error = %v", err)
	}

	if generic.Summary.Repositories != legacy.Summary.Repositories ||
		generic.Summary.Updates != legacy.Summary.Updates ||
		generic.Summary.UpdateTypes != legacy.Summary.UpdateTypes ||
		len(generic.Repositories) != len(legacy.Repositories) ||
		len(generic.Updates) != len(legacy.Updates) {
		t.Fatalf("generic facts = %#v, legacy facts = %#v", generic.Summary, legacy.Summary)
	}
}

func TestBuildPackagesEmptyArrays(t *testing.T) {
	t.Parallel()

	snapshot := dnfSnapshot()
	snapshot.Repositories = []packageinfo.Repository{}
	snapshot.Updates = []packageinfo.Update{}
	payload, err := results.BuildPackages(snapshot)
	if err != nil {
		t.Fatalf("BuildPackages() error = %v", err)
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(string(data), `"repositories":[]`) ||
		!strings.Contains(string(data), `"updates":[]`) {
		t.Fatalf("empty arrays encoded as null: %s", data)
	}
}

func TestBuildPackagesRejectsInvalidSnapshots(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 10, 0, 0, 0, time.UTC)
	age := int64(1800)
	validAPT := packageinfo.Snapshot{
		Backend: packageinfo.BackendAPT,
		Capabilities: packageinfo.Capabilities{
			Classification: packageinfo.ClassificationCapabilities{
				Security:    packageinfo.CapabilitySupported,
				Bugfix:      packageinfo.CapabilityUnsupported,
				Enhancement: packageinfo.CapabilityUnsupported,
				Other:       packageinfo.CapabilitySupported,
			},
			RepositoryAttribution: packageinfo.CapabilitySupported,
			RebootDetection:       packageinfo.CapabilitySupported,
			LastUpdate:            packageinfo.CapabilityBestEffort,
			MetadataAge:           packageinfo.CapabilitySupported,
		},
		Metadata:     packageinfo.Metadata{RefreshedAt: &now, AgeSeconds: &age},
		Repositories: []packageinfo.Repository{{ID: "apt-example", Name: "Ubuntu noble main"}},
		Updates: []packageinfo.Update{{
			Name:         "openssl",
			Version:      "3.0.13",
			Release:      "0ubuntu3.15",
			Arch:         "amd64",
			RepositoryID: "apt-example",
			Type:         packageinfo.UpdateTypeSecurity,
		}},
	}
	packageinfo.SetIdentity(packageinfo.BackendAPT, &validAPT.Updates[0])

	tests := []struct {
		name     string
		mutate   func(*packageinfo.Snapshot)
		wantText string
	}{
		{
			name: "unknown update type",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Updates[0].Type = packageinfo.UpdateTypeUnknown
			},
			wantText: "unknown classification",
		},
		{
			name: "APT bugfix",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Updates[0].Type = packageinfo.UpdateTypeBugfix
			},
			wantText: "unsupported classification",
		},
		{
			name: "duplicate APT package architecture",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Updates = append(snapshot.Updates, snapshot.Updates[0])
			},
			wantText: "duplicate APT update",
		},
		{
			name: "missing metadata",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Metadata.RefreshedAt = nil
			},
			wantText: "metadata age is incomplete",
		},
		{
			name: "inconsistent identifier",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Updates[0].Identifier = "wrong"
			},
			wantText: "inconsistent identifier",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			snapshot := validAPT
			snapshot.Repositories = append([]packageinfo.Repository(nil), validAPT.Repositories...)
			snapshot.Updates = append([]packageinfo.Update(nil), validAPT.Updates...)
			testCase.mutate(&snapshot)
			if _, err := results.BuildPackages(snapshot); err == nil || !strings.Contains(err.Error(), testCase.wantText) {
				t.Fatalf("BuildPackages() error = %v, want text %q", err, testCase.wantText)
			}
		})
	}
}

func dnfSnapshot() packageinfo.Snapshot {
	updates := []packageinfo.Update{
		{
			Name: "zlib", Epoch: "1", Version: "1.3.1", Release: "2.fc44", Arch: "x86_64",
			RepositoryID: "updates", Type: packageinfo.UpdateTypeSecurity,
		},
		{
			Name: "bash", Epoch: "0", Version: "5.2.37", Release: "4.fc44", Arch: "x86_64",
			RepositoryID: "updates", Type: packageinfo.UpdateTypeBugfix,
		},
	}
	for index := range updates {
		packageinfo.SetIdentity(packageinfo.BackendDNF, &updates[index])
	}

	return packageinfo.Snapshot{
		Backend: packageinfo.BackendDNF,
		Capabilities: packageinfo.Capabilities{
			Classification: packageinfo.ClassificationCapabilities{
				Security:    packageinfo.CapabilitySupported,
				Bugfix:      packageinfo.CapabilitySupported,
				Enhancement: packageinfo.CapabilitySupported,
				Other:       packageinfo.CapabilitySupported,
			},
			RepositoryAttribution: packageinfo.CapabilitySupported,
			RebootDetection:       packageinfo.CapabilitySupported,
			LastUpdate:            packageinfo.CapabilitySupported,
			MetadataAge:           packageinfo.CapabilityUnsupported,
		},
		Repositories: []packageinfo.Repository{{ID: "updates", Name: "Updates"}},
		Updates:      updates,
	}
}

func aptSnapshot() packageinfo.Snapshot {
	refreshedAt := time.Date(2026, time.August, 31, 10, 0, 0, 0, time.UTC)
	age := int64(1800)
	updates := []packageinfo.Update{
		{
			Name: "openssl", Epoch: "3", Version: "3.0.2", Release: "0ubuntu1.20", Arch: "amd64",
			RepositoryID: "apt-11111111111111111111111111111111", Type: packageinfo.UpdateTypeSecurity,
		},
		{
			Name: "curl", Version: "8.5.0", Release: "2ubuntu10.6", Arch: "amd64",
			RepositoryID: "apt-22222222222222222222222222222222", Type: packageinfo.UpdateTypeOther,
		},
	}
	for index := range updates {
		packageinfo.SetIdentity(packageinfo.BackendAPT, &updates[index])
	}

	return packageinfo.Snapshot{
		Backend: packageinfo.BackendAPT,
		Capabilities: packageinfo.Capabilities{
			Classification: packageinfo.ClassificationCapabilities{
				Security:    packageinfo.CapabilitySupported,
				Bugfix:      packageinfo.CapabilityUnsupported,
				Enhancement: packageinfo.CapabilityUnsupported,
				Other:       packageinfo.CapabilitySupported,
			},
			RepositoryAttribution: packageinfo.CapabilitySupported,
			RebootDetection:       packageinfo.CapabilitySupported,
			LastUpdate:            packageinfo.CapabilityBestEffort,
			MetadataAge:           packageinfo.CapabilitySupported,
		},
		Metadata: packageinfo.Metadata{RefreshedAt: &refreshedAt, AgeSeconds: &age},
		Repositories: []packageinfo.Repository{
			{ID: "apt-22222222222222222222222222222222", Name: "Ubuntu (noble-updates) [main]"},
			{ID: "apt-11111111111111111111111111111111", Name: "Ubuntu (noble-security) [main]"},
		},
		Updates:       updates,
		RebootPending: true,
	}
}
