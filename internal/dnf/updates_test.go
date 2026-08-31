package dnf_test

import (
	"reflect"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
)

func TestParseUpdates(t *testing.T) {
	t.Parallel()

	input := []byte(
		"code|0|1.134.0|1787078888.el8|x86_64|code\n" +
			"libei|0|1.6.0|2.fc44|x86_64|updates\n",
	)

	got, err := dnf.ParseUpdates(input)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}

	want := []dnf.Update{
		{
			Name:         "code",
			Epoch:        "0",
			Version:      "1.134.0",
			Release:      "1787078888.el8",
			Arch:         "x86_64",
			RepositoryID: "code",
			Type:         dnf.UpdateTypeOther,
		},
		{
			Name:         "libei",
			Epoch:        "0",
			Version:      "1.6.0",
			Release:      "2.fc44",
			Arch:         "x86_64",
			RepositoryID: "updates",
			Type:         dnf.UpdateTypeOther,
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parseUpdates() = %#v, want %#v", got, want)
	}
}

func TestParseUpdatesEmpty(t *testing.T) {
	t.Parallel()

	got, err := dnf.ParseUpdates(nil)
	if err != nil {
		t.Fatalf("parseUpdates() error = %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("parseUpdates() returned %d updates, want 0", len(got))
	}
}

func TestParseUpdatesMalformed(t *testing.T) {
	t.Parallel()

	_, err := dnf.ParseUpdates([]byte("broken|record\n"))
	if err == nil {
		t.Fatal("parseUpdates() expected error")
	}
}
