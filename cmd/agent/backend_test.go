package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

func TestParseBackendOption(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		options any
		want    string
		wantErr bool
	}{
		{name: "nil defaults to auto", want: backendAuto},
		{name: "empty map defaults to auto", options: map[string]any{}, want: backendAuto},
		{name: "auto", options: map[string]any{"Backend": "auto"}, want: backendAuto},
		{name: "dnf", options: map[string]any{"Backend": "dnf"}, want: backendDNF},
		{name: "apt", options: map[string]any{"Backend": "apt"}, want: backendAPT},
		{
			name: "Agent option tree",
			options: map[string]any{
				"Line": float64(1),
				"Name": "DNF",
				"Nodes": []any{
					map[string]any{
						"Line":  float64(2),
						"Name":  "System",
						"Nodes": []any{},
					},
					map[string]any{
						"Line":  float64(3),
						"Name":  "Backend",
						"Nodes": []any{map[string]any{"Line": float64(3), "Value": "ZG5m"}},
					},
				},
			},
			want: backendDNF,
		},
		{name: "invalid value", options: map[string]any{"Backend": "yum"}, wantErr: true},
		{name: "invalid type", options: map[string]any{"Backend": 1}, wantErr: true},
		{name: "unknown option", options: map[string]any{"Other": "dnf"}, wantErr: true},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseBackendOption(testCase.options)
			if testCase.wantErr {
				if !errors.Is(err, errInvalidBackendOption) {
					t.Fatalf("parseBackendOption() error = %v, want invalid option", err)
				}

				return
			}
			if err != nil || got != testCase.want {
				t.Fatalf("parseBackendOption() = (%q, %v), want (%q, nil)", got, err, testCase.want)
			}
		})
	}
}

func TestParseOSRelease(t *testing.T) {
	t.Parallel()

	values, err := parseOSRelease([]byte(
		"# comment\n" +
			"NAME=\"Example \\\"Linux\\\"\"\n" +
			"ID=example\n" +
			"ID_LIKE='debian ubuntu'\n",
	))
	if err != nil {
		t.Fatalf("parseOSRelease() error = %v", err)
	}
	if values["NAME"] != `Example "Linux"` || values["ID"] != "example" || values["ID_LIKE"] != "debian ubuntu" {
		t.Fatalf("parseOSRelease() = %#v", values)
	}
}

func TestDetectOSBackend(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		id      string
		idLike  string
		want    packageinfo.Backend
		wantErr error
	}{
		{name: "Debian exact", id: "debian", idLike: "rhel", want: packageinfo.BackendAPT},
		{name: "Ubuntu exact", id: "ubuntu", want: packageinfo.BackendAPT},
		{name: "Fedora exact", id: "fedora", idLike: "debian", want: packageinfo.BackendDNF},
		{name: "RHEL exact", id: "rhel", want: packageinfo.BackendDNF},
		{name: "Rocky exact", id: "rocky", want: packageinfo.BackendDNF},
		{name: "Alma exact", id: "almalinux", want: packageinfo.BackendDNF},
		{name: "CentOS exact", id: "centos", want: packageinfo.BackendDNF},
		{name: "APT derivative", id: "mint", idLike: "ubuntu debian", want: packageinfo.BackendAPT},
		{name: "DNF derivative", id: "custom", idLike: "fedora rhel", want: packageinfo.BackendDNF},
		{name: "ambiguous derivative", id: "custom", idLike: "debian rhel", wantErr: errAmbiguousBackend},
		{name: "unsupported", id: "alpine", wantErr: errUnsupportedBackend},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			got, err := detectOSBackend(testCase.id, testCase.idLike)
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) || !strings.Contains(err.Error(), "Plugins.DNF.Backend") {
					t.Fatalf("detectOSBackend() error = %v, want %v with override guidance", err, testCase.wantErr)
				}

				return
			}
			if err != nil || got != testCase.want {
				t.Fatalf("detectOSBackend() = (%s, %v), want (%s, nil)", got, err, testCase.want)
			}
		})
	}
}

func TestSelectBackendOverrideAndCommandRequirements(t *testing.T) {
	t.Parallel()

	allPaths := map[string]string{
		"dnf": "/usr/bin/dnf", "rpm": "/usr/bin/rpm", "uname": "/usr/bin/uname",
		"apt-get": "/usr/bin/apt-get", "apt-cache": "/usr/bin/apt-cache",
		"dpkg-query": "/usr/bin/dpkg-query", "dpkg": "/usr/bin/dpkg",
	}
	lookup := func(name string) (string, error) {
		path, exists := allPaths[name]
		if !exists {
			return "", fmt.Errorf("%s not found", name)
		}

		return path, nil
	}

	selection, err := selectBackend(backendDNF, []byte("ID=ubuntu\n"), lookup)
	if err != nil || selection.Backend != packageinfo.BackendDNF {
		t.Fatalf("explicit DNF selection = (%#v, %v)", selection, err)
	}
	selection, err = selectBackend(backendAPT, []byte("ID=fedora\n"), lookup)
	if err != nil || selection.Backend != packageinfo.BackendAPT {
		t.Fatalf("explicit APT selection = (%#v, %v)", selection, err)
	}

	_, err = selectBackend(backendAuto, []byte("ID=ubuntu\n"), func(name string) (string, error) {
		if name == "dpkg" {
			return "", errors.New("missing")
		}

		return "/usr/bin/" + name, nil
	})
	if err == nil || !strings.Contains(err.Error(), `apt backend requires executable "dpkg"`) {
		t.Fatalf("selectBackend() missing command error = %v", err)
	}

	_, err = selectBackend(backendAuto, []byte("ID=fedora\n"), func(name string) (string, error) {
		if name == "rpm" {
			return "", errors.New("missing")
		}

		return "/usr/bin/" + name, nil
	})
	if err == nil || !strings.Contains(err.Error(), `dnf backend requires executable "rpm"`) {
		t.Fatalf("selectBackend() missing DNF command error = %v", err)
	}
}

func TestParseOSReleaseRejectsMalformedInput(t *testing.T) {
	t.Parallel()

	for _, input := range []string{
		"NAME=missing-id\n",
		"ID=one\nID=two\n",
		"ID=\"unterminated\n",
		"ID =value\n",
	} {
		if _, err := parseOSRelease([]byte(input)); err == nil {
			t.Errorf("parseOSRelease(%q) error = nil", input)
		}
	}
}
