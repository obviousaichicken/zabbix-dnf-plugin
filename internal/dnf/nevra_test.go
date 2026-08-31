package dnf

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

func TestParseNEVRA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		value string
		want  NEVRA
	}{
		{
			value: "curl-8.12.1-4.el10_2.4.x86_64",
			want:  NEVRA{Name: "curl", Version: "8.12.1", Release: "4.el10_2.4", Arch: "x86_64"},
		},
		{
			value: "curl-minimal-7.76.1-40.el9_8.5.x86_64",
			want:  NEVRA{Name: "curl-minimal", Version: "7.76.1", Release: "40.el9_8.5", Arch: "x86_64"},
		},
		{
			value: "vim-data-2:9.2.390-1.fc42.noarch",
			want:  NEVRA{Name: "vim-data", Epoch: "2", Version: "9.2.390", Release: "1.fc42", Arch: "noarch"},
		},
		{
			value: "libstdc++-0:15.2.1-1.fc44.i686",
			want:  NEVRA{Name: "libstdc++", Epoch: "0", Version: "15.2.1", Release: "1.fc44", Arch: "i686"},
		},
		{
			value: "kernel-core-6.17.8-300.fc44.x86_64",
			want:  NEVRA{Name: "kernel-core", Version: "6.17.8", Release: "300.fc44", Arch: "x86_64"},
		},
		{
			value: "source-package-1.0-1.fc44.src",
			want:  NEVRA{Name: "source-package", Version: "1.0", Release: "1.fc44", Arch: "src"},
		},
	}

	for _, test := range tests {
		t.Run(test.value, func(t *testing.T) {
			t.Parallel()

			got, err := ParseNEVRA(test.value)
			if err != nil {
				t.Fatalf("ParseNEVRA() error = %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("ParseNEVRA() = %#v, want %#v", got, test.want)
			}
			if got.String() != test.value {
				t.Fatalf("NEVRA.String() = %q, want %q", got.String(), test.value)
			}
		})
	}
}

func TestParseNEVRARejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, value := range []string{
		"",
		" curl-1.0-1.x86_64",
		"curl-1.0-1.x86_64 ",
		"curl-1.0-1",
		"curl-1.0-1.",
		"curl-1.0.x86_64",
		"curl--1.x86_64",
		"curl-:1.0-1.x86_64",
		"curl-one:1.0-1.x86_64",
		"curl-1:2:1.0-1.x86_64",
		"curl/name-1.0-1.x86_64",
		"curl-1.0-1.x86.64",
		"curl-1.0-1.x86_64\x00",
	} {
		t.Run(value, func(t *testing.T) {
			t.Parallel()

			_, err := ParseNEVRA(value)
			if err == nil || !errors.Is(err, errInvalidNEVRA) {
				t.Fatalf("ParseNEVRA(%q) error = %v, want invalid NEVRA", value, err)
			}
		})
	}
}

func TestNEVRAMatchKeyNormalizesAbsentEpoch(t *testing.T) {
	t.Parallel()

	base := NEVRA{Name: "curl", Version: "8.0", Release: "1", Arch: "x86_64"}
	zero := base
	zero.Epoch = "0"
	none := base
	none.Epoch = "(none)"
	one := base
	one.Epoch = "1"

	if base.matchKey() != zero.matchKey() || base.matchKey() != none.matchKey() {
		t.Fatal("absent, zero, and (none) epochs did not normalize to one match key")
	}
	if base.matchKey() == one.matchKey() {
		t.Fatal("nonzero epoch unexpectedly matched an absent epoch")
	}
	if base.exactKey() == zero.exactKey() {
		t.Fatal("exact keys unexpectedly normalized epoch")
	}
}

func TestSetUpdateIdentityPreservesLegacyFormatting(t *testing.T) {
	t.Parallel()

	for _, update := range []packageinfo.Update{
		{Name: "bash", Epoch: "0", Version: "5.2", Release: "1.el9", Arch: "x86_64"},
		{Name: "kernel-core", Version: "6.17", Release: "1.fc44", Arch: "x86_64"},
		{Name: "legacy", Epoch: "(none)", Version: "1", Arch: "noarch"},
	} {
		want := update
		packageinfo.SetIdentity(packageinfo.BackendDNF, &want)
		got := update
		setUpdateIdentity(&got)
		if got.FullVersion != want.FullVersion || got.Identifier != want.Identifier {
			t.Fatalf("setUpdateIdentity(%#v) = (%q, %q), want (%q, %q)", update, got.FullVersion, got.Identifier, want.FullVersion, want.Identifier)
		}
	}
}

func TestUpdatePackageKeyRemainsExact(t *testing.T) {
	t.Parallel()

	update := Update{Name: "curl", Version: "8", Release: "1", Arch: "x86_64", RepositoryID: "updates"}
	withEpoch := update
	withEpoch.Epoch = "0"
	if updatePackageKey(update) == updatePackageKey(withEpoch) {
		t.Fatal("updatePackageKey normalized an epoch and changed legacy classification semantics")
	}
	if !strings.HasSuffix(updatePackageKey(update), "\x00updates") {
		t.Fatal("updatePackageKey omitted repository identity")
	}
}
