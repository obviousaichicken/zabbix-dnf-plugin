package apt

import (
	"context"
	"io/fs"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

func TestCollectBuildsCompleteAPTSnapshot(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: readAPTFixture(t, "debian13", "indextargets.txt")},
		{stdout: readAPTFixture(t, "debian13", "dpkg-query.txt")},
		{stdout: readAPTFixture(t, "debian13", "policy.txt")},
		{exitCode: 0},
	}}
	historyData := []byte(`Start-Date: 2026-08-30  09:00:00
Upgrade: pkg:amd64 (1.0, 2.0)
End-Date: 2026-08-30  09:01:00
`)
	historyPath := "/virtual/apt/history.log"
	historyFS := &fakeHistoryFileSystem{
		entries: []fs.DirEntry{fakeHistoryDirEntry{name: historyBaseName, mode: 0o600}},
		files:   map[string][]byte{historyPath: historyData},
	}
	client, err := newClientWithSystemForTest(
		runner,
		testAPTPaths(),
		func(path string) (fs.FileInfo, error) {
			if path == "/virtual/reboot-required" {
				return fakeFileInfo{mode: 0o644, modified: now}, nil
			}

			return fakeFileInfo{mode: 0o644, modified: now.Add(-time.Hour)}, nil
		},
		func() time.Time { return now },
		historyFS,
		"/virtual/apt",
		"/virtual/reboot-required",
		time.UTC,
	)
	if err != nil {
		t.Fatalf("construct APT client: %v", err)
	}

	snapshot, err := client.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if snapshot.Backend != packageinfo.BackendAPT || !snapshot.RebootPending || snapshot.LastUpdate == nil {
		t.Fatalf("snapshot identity/reboot/history = %#v", snapshot)
	}
	if snapshot.LastUpdate.Result != packageinfo.LastUpdateResultSuccess ||
		snapshot.Capabilities.LastUpdate != packageinfo.CapabilityBestEffort ||
		snapshot.Capabilities.Classification.Bugfix != packageinfo.CapabilityUnsupported ||
		snapshot.Capabilities.MetadataAge != packageinfo.CapabilitySupported {
		t.Errorf("snapshot capabilities/history = %#v / %#v", snapshot.Capabilities, snapshot.LastUpdate)
	}
	if err := snapshot.ValidateBasic(); err != nil {
		t.Errorf("snapshot validation: %v", err)
	}
}

func TestCollectRepresentsMissingHistoryAsNotRecorded(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.August, 31, 12, 0, 0, 0, time.UTC)
	runner := &fakeAPTRunner{responses: []fakeAPTResponse{
		{stdout: readAPTFixture(t, "debian12", "indextargets.txt")},
		{stdout: readAPTFixture(t, "debian12", "dpkg-query.txt")},
		{stdout: readAPTFixture(t, "debian12", "policy.txt")},
	}}
	historyFS := &fakeHistoryFileSystem{readDirErr: fs.ErrNotExist}
	client, err := newClientWithSystemForTest(
		runner,
		testAPTPaths(),
		func(path string) (fs.FileInfo, error) {
			if path == "/virtual/reboot-required" {
				return nil, fs.ErrNotExist
			}

			return fakeFileInfo{mode: 0o644, modified: now}, nil
		},
		func() time.Time { return now },
		historyFS,
		"/virtual/apt",
		"/virtual/reboot-required",
		time.UTC,
	)
	if err != nil {
		t.Fatalf("construct APT client: %v", err)
	}

	snapshot, err := client.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if snapshot.LastUpdate != nil || snapshot.RebootPending || len(snapshot.Updates) != 0 {
		t.Fatalf("snapshot = %#v, want not-recorded history, no reboot, no updates", snapshot)
	}
}
