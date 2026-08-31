//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/apt"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/results"
)

func TestAPTSmoke(t *testing.T) {
	const collectionDeadline = 30 * time.Second

	client, err := apt.New(command.Runner{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), collectionDeadline)
	defer cancel()
	started := time.Now()

	snapshot, err := client.Collect(ctx)
	if err != nil {
		t.Fatalf("Collect() error = %v", err)
	}
	if snapshot.Backend != packageinfo.BackendAPT {
		t.Fatalf("Collect().Backend = %s, want apt", snapshot.Backend)
	}
	if len(snapshot.Repositories) == 0 {
		t.Fatal("Collect().Repositories is empty after apt-get update")
	}
	if snapshot.Metadata.RefreshedAt == nil || snapshot.Metadata.AgeSeconds == nil ||
		*snapshot.Metadata.AgeSeconds < 0 {
		t.Fatalf("Collect().Metadata = %#v, want complete non-negative age", snapshot.Metadata)
	}

	security := 0
	other := 0
	for _, update := range snapshot.Updates {
		switch update.Type {
		case packageinfo.UpdateTypeSecurity:
			security++
		case packageinfo.UpdateTypeOther:
			other++
		default:
			t.Fatalf("APT update has unsupported classification %s: %#v", update.Type, update)
		}
	}
	if security+other != len(snapshot.Updates) {
		t.Fatalf("security + other = %d, updates = %d", security+other, len(snapshot.Updates))
	}

	payload, err := results.BuildPackages(snapshot)
	if err != nil {
		t.Fatalf("BuildPackages() error = %v", err)
	}
	if !payload.Collection.Complete || payload.Backend != "apt" ||
		payload.Summary.Updates != len(snapshot.Updates) {
		t.Fatalf("packages.get payload invariants failed: %#v", payload)
	}

	t.Logf(
		"repositories=%d updates=%d security=%d other=%d reboot_pending=%t last_update=%v metadata_age=%d duration=%s",
		len(snapshot.Repositories),
		len(snapshot.Updates),
		security,
		other,
		snapshot.RebootPending,
		snapshot.LastUpdate,
		*snapshot.Metadata.AgeSeconds,
		time.Since(started),
	)
}
