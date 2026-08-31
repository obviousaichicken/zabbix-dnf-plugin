package results_test

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/results"
)

const (
	updatesRepository = "updates"
	codeRepository    = "code"
	fedoraRepository  = "fedora"
	updatesName       = "Updates"
	codeName          = "code"
	libeiName         = "libei"
	x8664Arch         = "x86_64"
)

type expectedUpdate struct {
	repositoryID string
	name         string
	arch         string
}

func newUpdate(repositoryID, name, arch string) dnf.Update {
	return dnf.Update{
		Name:         name,
		Epoch:        "",
		Version:      "",
		Release:      "",
		Arch:         arch,
		RepositoryID: repositoryID,
	}
}

func assertSortedUpdates(t *testing.T, payload results.Payload, want []expectedUpdate) {
	t.Helper()

	if len(payload.Updates) != len(want) {
		t.Fatalf(
			"got %d updates, want %d",
			len(payload.Updates),
			len(want),
		)
	}

	for updateIndex, expected := range want {
		got := payload.Updates[updateIndex]

		if got.RepositoryID != expected.repositoryID ||
			got.Name != expected.name ||
			got.Arch != expected.arch {
			t.Errorf(
				"Updates[%d] = (%q, %q, %q), want (%q, %q, %q)",
				updateIndex,
				got.RepositoryID,
				got.Name,
				got.Arch,
				expected.repositoryID,
				expected.name,
				expected.arch,
			)
		}
	}
}

func TestBuildSortsRepositoriesByID(t *testing.T) {
	t.Parallel()

	repositories := []dnf.Repository{
		{ID: updatesRepository, Name: updatesName},
		{ID: codeRepository, Name: "Visual Studio Code"},
		{ID: fedoraRepository, Name: "Fedora"},
	}

	payload, err := results.Build(repositories, nil)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := []string{
		"code",
		"fedora",
		"updates",
	}

	if len(payload.Repositories) != len(want) {
		t.Fatalf(
			"got %d repositories, want %d",
			len(payload.Repositories),
			len(want),
		)
	}

	for repositoryIndex, wantID := range want {
		if got := payload.Repositories[repositoryIndex].ID; got != wantID {
			t.Errorf(
				"Repositories[%d].ID = %q, want %q",
				repositoryIndex,
				got,
				wantID,
			)
		}
	}
}

func TestBuildSortsUpdatesByRepositoryNameAndArch(t *testing.T) {
	t.Parallel()

	repositories := []dnf.Repository{
		{ID: updatesRepository, Name: updatesName},
		{ID: codeRepository, Name: "Visual Studio Code"},
	}

	updates := []dnf.Update{
		newUpdate(updatesRepository, libeiName, x8664Arch),
		newUpdate(updatesRepository, "libevdev", x8664Arch),
		newUpdate(codeRepository, codeName, x8664Arch),
		newUpdate(updatesRepository, libeiName, "i686"),
		newUpdate(updatesRepository, "libeis", x8664Arch),
	}

	payload, err := results.Build(repositories, updates)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	want := []expectedUpdate{
		{codeRepository, codeName, x8664Arch},
		{updatesRepository, libeiName, "i686"},
		{updatesRepository, libeiName, x8664Arch},
		{updatesRepository, "libeis", x8664Arch},
		{updatesRepository, "libevdev", x8664Arch},
	}

	if len(payload.Updates) != len(want) {
		t.Fatalf(
			"got %d updates, want %d",
			len(payload.Updates),
			len(want),
		)
	}

	assertSortedUpdates(t, payload, want)
}

func TestBuildSummaryCountsClassifiedUpdates(t *testing.T) {
	t.Parallel()

	repositories := []dnf.Repository{
		{ID: updatesRepository, Name: updatesName},
	}
	updates := []dnf.Update{
		newTypedUpdate("security", dnf.UpdateTypeSecurity),
		newTypedUpdate("bugfix", dnf.UpdateTypeBugfix),
		newTypedUpdate("enhancement", dnf.UpdateTypeEnhancement),
		newTypedUpdate("other", dnf.UpdateTypeOther),
	}
	for index := range updates {
		updates[index].RepositoryID = updatesRepository
	}

	payload, err := results.Build(repositories, updates)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	if !payload.Summary.UpdatesPending {
		t.Fatal("Summary.UpdatesPending = false, want true")
	}

	want := results.UpdateTypeCounts{
		Security:    1,
		Bugfix:      1,
		Enhancement: 1,
		Other:       1,
	}
	if payload.Summary.UpdateTypes != want {
		t.Fatalf("Summary.UpdateTypes = %#v, want %#v", payload.Summary.UpdateTypes, want)
	}

	counts := payload.Summary.UpdateTypes
	if got := counts.Security + counts.Bugfix + counts.Enhancement + counts.Other; got != payload.Summary.Updates {
		t.Fatalf("update type counts = %d, want %d", got, payload.Summary.Updates)
	}
}

func TestBuildSummaryUsesExpectedJSONShape(t *testing.T) {
	t.Parallel()

	payload, err := results.Build(
		[]dnf.Repository{{ID: updatesRepository, Name: updatesName}},
		nil,
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	emptyData, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if !strings.Contains(
		string(emptyData),
		`"last_update":{"timestamp":null,"result":"not_recorded"}`,
	) {
		t.Fatalf("empty JSON payload has invalid last_update: %s", emptyData)
	}
	if !strings.Contains(string(emptyData), `"reboot_pending":false`) {
		t.Fatalf("empty JSON payload has invalid reboot status: %s", emptyData)
	}
	if !strings.Contains(string(emptyData), `"classification":{"complete":true,"failed_categories":[]}`) {
		t.Fatalf("empty JSON payload has invalid classification status: %s", emptyData)
	}
	if !strings.Contains(string(emptyData), `"collection":{"complete":true,"duration_ms":0}`) {
		t.Fatalf("empty JSON payload has invalid collection metadata: %s", emptyData)
	}

	payload.Summary.RebootPending = true
	timestamp := time.Date(2026, time.August, 19, 21, 14, 8, 0, time.UTC)
	payload.Summary.LastUpdate = results.NewLastUpdate(&dnf.LastUpdate{
		Timestamp: timestamp,
		Result:    "success",
	})

	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	jsonText := string(data)
	for _, field := range []string{
		`"updates_pending":false`,
		`"reboot_pending":true`,
		`"update_types":{"security":0,"bugfix":0,"enhancement":0,"other":0}`,
		`"last_update":{"timestamp":"2026-08-19T21:14:08Z","result":"success"}`,
	} {
		if !strings.Contains(jsonText, field) {
			t.Fatalf("JSON payload does not contain %s: %s", field, jsonText)
		}
	}
}

func TestLegacyDNFGetGolden(t *testing.T) {
	t.Parallel()

	payload, err := results.Build(
		[]dnf.Repository{
			{ID: updatesRepository, Name: updatesName},
			{ID: codeRepository, Name: "Visual Studio Code"},
		},
		[]dnf.Update{
			{
				RepositoryID: updatesRepository,
				Name:         "zlib",
				Epoch:        "1",
				Version:      "1.3.1",
				Release:      "2.fc44",
				Arch:         x8664Arch,
				Type:         dnf.UpdateTypeSecurity,
			},
			{
				RepositoryID: codeRepository,
				Name:         codeName,
				Version:      "1.104.0",
				Release:      "1755709794.el8",
				Arch:         x8664Arch,
				Type:         dnf.UpdateTypeOther,
			},
			{
				RepositoryID: updatesRepository,
				Name:         "bash",
				Epoch:        "0",
				Version:      "5.2.37",
				Release:      "4.fc44",
				Arch:         x8664Arch,
				Type:         dnf.UpdateTypeBugfix,
			},
		},
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}

	timestamp := time.Date(2026, time.August, 19, 21, 14, 8, 0, time.UTC)
	payload.Summary.RebootPending = true
	payload.Summary.LastUpdate = results.NewLastUpdate(&dnf.LastUpdate{
		Timestamp: timestamp,
		Result:    dnf.LastUpdateResultSuccess,
	})

	got, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	want, err := os.ReadFile("testdata/dnf-get.golden.json")
	if err != nil {
		t.Fatalf("read golden payload: %v", err)
	}
	want = bytes.TrimSuffix(want, []byte("\n"))

	if !bytes.Equal(got, want) {
		t.Fatalf("legacy dnf.get payload changed\ngot:  %s\nwant: %s", got, want)
	}
}

func TestBuildRejectsDuplicateRepositoryIDs(t *testing.T) {
	t.Parallel()

	repositories := []dnf.Repository{
		{
			ID:   updatesRepository,
			Name: updatesName,
		},
		{
			ID:   updatesRepository,
			Name: "Duplicate Updates",
		},
	}

	_, err := results.Build(repositories, nil)
	if err == nil {
		t.Fatal("Build() expected error")
	}

	if !strings.Contains(err.Error(), `duplicate repository ID "updates"`) {
		t.Fatalf(
			"Build() error = %q, want duplicate repository error",
			err,
		)
	}
}

func TestBuildRejectsUnknownRepositoryReference(t *testing.T) {
	t.Parallel()

	repositories := []dnf.Repository{
		{
			ID:   updatesRepository,
			Name: updatesName,
		},
	}

	updates := []dnf.Update{
		{
			RepositoryID: "missing",
			Name:         libeiName,
			Epoch:        "0",
			Version:      "1.6.0",
			Release:      "2.fc44",
			Arch:         x8664Arch,
		},
	}

	_, err := results.Build(repositories, updates)
	if err == nil {
		t.Fatal("Build() expected error")
	}

	if !strings.Contains(
		err.Error(),
		`update "libei" references unknown repository "missing"`,
	) {
		t.Fatalf(
			"Build() error = %q, want unknown repository error",
			err,
		)
	}
}

func newTypedUpdate(name string, updateType dnf.UpdateType) dnf.Update {
	return dnf.Update{
		Name:         name,
		Epoch:        "0",
		Version:      "1.0",
		Release:      "1",
		Arch:         x8664Arch,
		RepositoryID: updatesRepository,
		Type:         updateType,
	}
}
