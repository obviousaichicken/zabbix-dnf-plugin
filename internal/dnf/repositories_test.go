package dnf_test

import (
	"reflect"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/dnf"
)

const baseOSRepository = "baseos"

func TestParseRepositories(t *testing.T) {
	t.Parallel()

	input := []byte(
		"repo id                         repo name\n" +
			"baseos                          Red Hat Enterprise Linux 9 - BaseOS\n" +
			"appstream                       Red Hat Enterprise Linux 9 - AppStream\n",
	)

	got, err := dnf.ParseRepositories(input)
	if err != nil {
		t.Fatalf("ParseRepositories() error = %v", err)
	}

	want := []dnf.Repository{
		{ID: baseOSRepository, Name: "Red Hat Enterprise Linux 9 - BaseOS"},
		{ID: "appstream", Name: "Red Hat Enterprise Linux 9 - AppStream"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRepositories() = %#v, want %#v", got, want)
	}
}

func TestParseRepositoriesWithStatus(t *testing.T) {
	t.Parallel()

	input := []byte(
		"repo id                         repo name                                      status\n" +
			"baseos                          Red Hat Enterprise Linux 8 - BaseOS           12,345\n",
	)

	got, err := dnf.ParseRepositories(input)
	if err != nil {
		t.Fatalf("ParseRepositories() error = %v", err)
	}

	want := []dnf.Repository{
		{ID: baseOSRepository, Name: "Red Hat Enterprise Linux 8 - BaseOS"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRepositories() = %#v, want %#v", got, want)
	}
}

func TestParseRepositoriesAcceptsRepolistIDs(t *testing.T) {
	t.Parallel()

	input := []byte(
		"repo id repo name\n" +
			"repolist:custom Colon Repository\n" +
			"repolist: 123\n",
	)

	got, err := dnf.ParseRepositories(input)
	if err != nil {
		t.Fatalf("ParseRepositories() error = %v", err)
	}

	want := []dnf.Repository{
		{ID: "repolist:custom", Name: "Colon Repository"},
		{ID: "repolist:", Name: "123"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRepositories() = %#v, want %#v", got, want)
	}
}

func TestParseRepositoriesEmpty(t *testing.T) {
	t.Parallel()

	got, err := dnf.ParseRepositories(nil)
	if err != nil {
		t.Fatalf("ParseRepositories() error = %v", err)
	}

	if len(got) != 0 {
		t.Fatalf("ParseRepositories() returned %d repositories, want 0", len(got))
	}
}

func TestParseRepositoriesIgnoresPreamble(t *testing.T) {
	t.Parallel()

	input := []byte(
		"Updating Subscription Management repositories.\n" +
			"repo id repo name\n" +
			"baseos Red Hat Enterprise Linux 9 - BaseOS\n",
	)

	got, err := dnf.ParseRepositories(input)
	if err != nil {
		t.Fatalf("ParseRepositories() error = %v", err)
	}

	want := []dnf.Repository{
		{ID: baseOSRepository, Name: "Red Hat Enterprise Linux 9 - BaseOS"},
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseRepositories() = %#v, want %#v", got, want)
	}
}

func TestParseRepositoriesRejectsUnexpectedOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{
			name:  "missing header",
			input: "baseos Red Hat Enterprise Linux 9 - BaseOS\n",
		},
		{
			name:  "invalid header",
			input: "repo id repository description\n",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			_, err := dnf.ParseRepositories([]byte(testCase.input))
			if err == nil {
				t.Fatal("ParseRepositories() expected error")
			}
		})
	}
}
