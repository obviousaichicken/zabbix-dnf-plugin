package dnf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

const (
	repositoryFields             = 2
	repositoryHeaderFields       = 4
	repositoryHeaderStatusFields = 5
)

var errInvalidRepolistOutput = errors.New("invalid repolist output")

// ParseRepositories parses DNF repository output.
func ParseRepositories(data []byte) ([]Repository, error) {
	repositories := make([]Repository, 0)

	scanner := bufio.NewScanner(bytes.NewReader(data))

	hasContent := false
	headerFound := false
	hasStatusColumn := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		hasContent = true

		if !headerFound {
			var valid bool

			hasStatusColumn, valid = parseRepositoryHeader(line)
			if !valid {
				continue
			}

			headerFound = true

			continue
		}

		repository, err := parseRepositoryRow(line, hasStatusColumn)
		if err != nil {
			return nil, err
		}

		repositories = append(repositories, repository)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read repolist output: %w", err)
	}

	if hasContent && !headerFound {
		return nil, errInvalidRepolistOutput
	}

	return repositories, nil
}

func parseRepositoryRow(line string, hasStatusColumn bool) (Repository, error) {
	fields := strings.Fields(line)
	if len(fields) < repositoryFields {
		return Repository{}, fmt.Errorf("%w: %q", errInvalidRepolistOutput, line)
	}

	nameFields := fields[1:]

	if hasStatusColumn {
		if len(nameFields) < repositoryFields {
			return Repository{}, fmt.Errorf("%w: %q", errInvalidRepolistOutput, line)
		}

		nameFields = nameFields[:len(nameFields)-1]
	}

	return Repository{
		ID:   fields[0],
		Name: strings.Join(nameFields, " "),
	}, nil
}

func parseRepositoryHeader(line string) (bool, bool) {
	fields := strings.Fields(strings.ToLower(line))
	if len(fields) != repositoryHeaderFields &&
		len(fields) != repositoryHeaderStatusFields {
		return false, false
	}

	if fields[0] != "repo" || fields[1] != "id" ||
		fields[2] != "repo" || fields[3] != "name" {
		return false, false
	}

	if len(fields) == repositoryHeaderStatusFields {
		if fields[4] != "status" {
			return false, false
		}

		return true, true
	}

	return false, true
}
