package dnf

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

const updateFields = 6

var errInvalidRepoqueryOutput = errors.New("invalid repoquery output")

// ParseUpdates parses DNF update-query output.
func ParseUpdates(data []byte) ([]Update, error) {
	updates := make([]Update, 0)

	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.SplitN(line, "|", updateFields)
		if len(fields) != updateFields {
			return nil, fmt.Errorf("%w: %q", errInvalidRepoqueryOutput, line)
		}

		updates = append(updates, Update{
			Name:         fields[0],
			Epoch:        fields[1],
			Version:      fields[2],
			Release:      fields[3],
			Arch:         fields[4],
			RepositoryID: fields[5],
			Type:         UpdateTypeOther,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read package update output: %w", err)
	}

	return updates, nil
}
