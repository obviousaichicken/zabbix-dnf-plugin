package main

import (
	"bufio"
	"os"
	"regexp"
	"strings"
	"testing"
)

var templateUUIDPattern = regexp.MustCompile(`^\s*- uuid: ([0-9a-f]{32})$`)

func TestCombinedTemplateUUIDBaseline(t *testing.T) {
	t.Parallel()

	templateData, err := os.ReadFile("../../template-dnf-by-zabbix-agent2.yaml")
	if err != nil {
		t.Fatalf("read combined template: %v", err)
	}

	got := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(string(templateData)))
	for scanner.Scan() {
		matches := templateUUIDPattern.FindStringSubmatch(scanner.Text())
		if len(matches) == 2 {
			got = append(got, matches[1])
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan combined template: %v", err)
	}

	wantData, err := os.ReadFile("testdata/dnf-template-uuids.golden")
	if err != nil {
		t.Fatalf("read UUID baseline: %v", err)
	}
	want := strings.Fields(string(wantData))

	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("combined template UUID baseline changed\ngot:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
