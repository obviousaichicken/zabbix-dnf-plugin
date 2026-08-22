//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
)

func TestDNFSmoke(t *testing.T) {
	const collectionDeadline = 30 * time.Second

	client, err := dnf.New(command.Runner{})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), collectionDeadline)
	defer cancel()
	started := time.Now()

	repositories, err := client.Repositories(ctx)
	if err != nil {
		t.Fatalf("Repositories() error = %v", err)
	}
	if len(repositories) == 0 {
		t.Fatal("Repositories() returned no enabled repositories")
	}

	updates, err := client.Updates(ctx)
	if err != nil {
		t.Fatalf("Updates() error = %v", err)
	}

	rebootPending, err := client.RebootPending(ctx)
	if err != nil {
		t.Fatalf("RebootPending() error = %v", err)
	}

	lastUpdate, err := client.LastUpdate(ctx)
	if err != nil {
		t.Fatalf("LastUpdate() error = %v", err)
	}

	t.Logf(
		"repositories=%d updates=%d reboot_pending=%t last_update=%v duration=%s",
		len(repositories),
		len(updates),
		rebootPending,
		lastUpdate,
		time.Since(started),
	)
}
