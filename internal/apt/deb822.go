package apt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strings"
)

const (
	maxRepositoryIndexBytes = 8 << 20
	maxDeb822LineBytes      = 1 << 20
	maxDeb822Fields         = 256
)

type deb822Record map[string]string

// parseDeb822 parses the bounded, paragraph-oriented output emitted by
// apt-get indextargets. Field names are treated case-insensitively and values
// are never copied into errors because repository URLs can contain secrets.
func parseDeb822(data []byte) ([]deb822Record, error) {
	if len(data) > maxRepositoryIndexBytes {
		return nil, fmt.Errorf("repository index output exceeds %d bytes", maxRepositoryIndexBytes)
	}

	var records []deb822Record
	record := make(deb822Record)
	currentField := ""
	lineNumber := 0
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), maxDeb822LineBytes)

	flush := func() {
		if len(record) != 0 {
			records = append(records, record)
			record = make(deb822Record)
		}
		currentField = ""
	}

	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.IndexByte(line, 0) >= 0 {
			return nil, fmt.Errorf("malformed deb822 line %d: NUL byte", lineNumber)
		}
		if line == "" {
			flush()
			continue
		}
		if line[0] == '#' {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if currentField == "" {
				return nil, fmt.Errorf("malformed deb822 line %d: orphan continuation", lineNumber)
			}
			record[currentField] += "\n" + strings.TrimSpace(line)
			continue
		}

		separator := strings.IndexByte(line, ':')
		if separator <= 0 {
			return nil, fmt.Errorf("malformed deb822 line %d: missing field separator", lineNumber)
		}
		name := line[:separator]
		if !validDeb822FieldName(name) {
			return nil, fmt.Errorf("malformed deb822 line %d: invalid field name", lineNumber)
		}
		name = strings.ToLower(name)
		if _, exists := record[name]; exists {
			return nil, fmt.Errorf("malformed deb822 record: duplicate field %q", name)
		}
		if len(record) >= maxDeb822Fields {
			return nil, fmt.Errorf("malformed deb822 record: more than %d fields", maxDeb822Fields)
		}

		record[name] = strings.TrimSpace(line[separator+1:])
		currentField = name
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("malformed deb822 input: line exceeds parser limit")
	}
	flush()

	return records, nil
}

func validDeb822FieldName(name string) bool {
	for index, character := range []byte(name) {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			index > 0 && character >= '0' && character <= '9' ||
			index > 0 && character == '-' {
			continue
		}

		return false
	}

	return name != ""
}
