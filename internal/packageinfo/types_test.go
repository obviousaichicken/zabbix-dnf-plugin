package packageinfo_test

import (
	"strings"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

func TestEnumsUseUnknownZeroValues(t *testing.T) {
	t.Parallel()

	if packageinfo.BackendUnknown != 0 || packageinfo.BackendUnknown.Valid() {
		t.Fatal("Backend zero value must be unknown and invalid")
	}
	if packageinfo.CapabilityUnknown != 0 || packageinfo.CapabilityUnknown.Valid() {
		t.Fatal("Capability zero value must be unknown and invalid")
	}
	if packageinfo.UpdateTypeUnknown != 0 || packageinfo.UpdateTypeUnknown.Valid() {
		t.Fatal("UpdateType zero value must be unknown and invalid")
	}
}

func TestEnumStrings(t *testing.T) {
	t.Parallel()

	if got := packageinfo.BackendAPT.String(); got != "apt" {
		t.Fatalf("BackendAPT.String() = %q, want apt", got)
	}
	if got := packageinfo.CapabilityBestEffort.String(); got != "best_effort" {
		t.Fatalf("CapabilityBestEffort.String() = %q, want best_effort", got)
	}
	if got := packageinfo.UpdateTypeEnhancement.String(); got != "enhancement" {
		t.Fatalf("UpdateTypeEnhancement.String() = %q, want enhancement", got)
	}
}

func TestSnapshotValidateBasic(t *testing.T) {
	t.Parallel()

	capabilities := packageinfo.Capabilities{
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
	}

	valid := packageinfo.Snapshot{
		Backend:      packageinfo.BackendAPT,
		Capabilities: capabilities,
		Repositories: []packageinfo.Repository{{ID: "apt-example", Name: "Example"}},
		Updates: []packageinfo.Update{{
			Name:         "openssl",
			RepositoryID: "apt-example",
			Type:         packageinfo.UpdateTypeSecurity,
		}},
	}
	if err := valid.ValidateBasic(); err != nil {
		t.Fatalf("ValidateBasic() error = %v", err)
	}

	tests := []struct {
		name     string
		mutate   func(*packageinfo.Snapshot)
		wantText string
	}{
		{
			name:     "unknown backend",
			mutate:   func(snapshot *packageinfo.Snapshot) { snapshot.Backend = packageinfo.BackendUnknown },
			wantText: "unknown package backend",
		},
		{
			name: "unknown capability",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Capabilities.MetadataAge = packageinfo.CapabilityUnknown
			},
			wantText: "metadata_age",
		},
		{
			name: "unknown update type",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Updates[0].Type = packageinfo.UpdateTypeUnknown
			},
			wantText: "unknown classification",
		},
		{
			name: "unknown repository",
			mutate: func(snapshot *packageinfo.Snapshot) {
				snapshot.Updates[0].RepositoryID = "missing"
			},
			wantText: "unknown repository",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			snapshot := valid
			snapshot.Repositories = append([]packageinfo.Repository(nil), valid.Repositories...)
			snapshot.Updates = append([]packageinfo.Update(nil), valid.Updates...)
			testCase.mutate(&snapshot)
			if err := snapshot.ValidateBasic(); err == nil || !strings.Contains(err.Error(), testCase.wantText) {
				t.Fatalf("ValidateBasic() error = %v, want text %q", err, testCase.wantText)
			}
		})
	}
}
