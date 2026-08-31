package packageinfo_test

import (
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

func TestSetIdentity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		backend     packageinfo.Backend
		update      packageinfo.Update
		wantVersion string
		wantID      string
	}{
		{
			name:    "DNF epoch",
			backend: packageinfo.BackendDNF,
			update: packageinfo.Update{
				Name: "bash", Epoch: "0", Version: "5.2", Release: "1.el9", Arch: "x86_64",
			},
			wantVersion: "0:5.2-1.el9",
			wantID:      "bash-0:5.2-1.el9.x86_64",
		},
		{
			name:    "DNF absent epoch",
			backend: packageinfo.BackendDNF,
			update: packageinfo.Update{
				Name: "kernel-core", Version: "6.17", Release: "1.fc44", Arch: "x86_64",
			},
			wantVersion: "6.17-1.fc44",
			wantID:      "kernel-core-6.17-1.fc44.x86_64",
		},
		{
			name:    "APT Debian version",
			backend: packageinfo.BackendAPT,
			update: packageinfo.Update{
				Name: "libproc2-0", Epoch: "2", Version: "4.0.4", Release: "4ubuntu3.3", Arch: "amd64",
			},
			wantVersion: "2:4.0.4-4ubuntu3.3",
			wantID:      "libproc2-0:amd64=2:4.0.4-4ubuntu3.3",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			update := testCase.update
			packageinfo.SetIdentity(testCase.backend, &update)
			if update.FullVersion != testCase.wantVersion || update.Identifier != testCase.wantID {
				t.Fatalf("SetIdentity() = (%q, %q), want (%q, %q)", update.FullVersion, update.Identifier, testCase.wantVersion, testCase.wantID)
			}
		})
	}
}
