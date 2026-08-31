package apt

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

const (
	defaultHistoryDirectory = "/var/log/apt"
	historyBaseName         = "history.log"
	maxHistoryFiles         = 32
	maxHistoryFileBytes     = 8 << 20
	maxHistoryTotalBytes    = 32 << 20
	maxHistoryLineBytes     = 1 << 20
	maxHistoryStanzaBytes   = 2 << 20
	maxHistoryFields        = 128
	historyTimestampLayout  = "2006-01-02 15:04:05"
)

type historyFileSystem interface {
	ReadDir(string) ([]fs.DirEntry, error)
	Open(string) (io.ReadCloser, error)
}

type osHistoryFileSystem struct{}

func (osHistoryFileSystem) ReadDir(name string) ([]fs.DirEntry, error) {
	return os.ReadDir(name)
}

func (osHistoryFileSystem) Open(name string) (io.ReadCloser, error) {
	return os.Open(name)
}

// HistoryReader reads APT's best-effort transaction history without invoking
// a command or exposing file contents in errors.
type HistoryReader struct {
	fileSystem historyFileSystem
	directory  string
	location   *time.Location
}

func newHistoryReader(
	fileSystem historyFileSystem,
	directory string,
	location *time.Location,
) (*HistoryReader, error) {
	if fileSystem == nil {
		return nil, errors.New("history filesystem is required")
	}
	if directory == "" || !filepath.IsAbs(directory) {
		return nil, errors.New("history directory must be an absolute path")
	}
	if location == nil {
		return nil, errors.New("history timezone is required")
	}

	return &HistoryReader{fileSystem: fileSystem, directory: directory, location: location}, nil
}

func newHistoryReaderForTest(
	fileSystem historyFileSystem,
	directory string,
	location *time.Location,
) (*HistoryReader, error) {
	return newHistoryReader(fileSystem, directory, location)
}

// LastUpdate returns the newest retained completed or explicitly failed APT
// transaction containing Upgrade. A nil result means not recorded.
func (reader *HistoryReader) LastUpdate(ctx context.Context) (*packageinfo.LastUpdate, error) {
	files, err := reader.historyFiles(ctx)
	if err != nil {
		return nil, err
	}
	remainingBytes := int64(maxHistoryTotalBytes)
	for _, file := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data, readErr := reader.readHistoryFile(file, &remainingBytes)
		if readErr != nil {
			return nil, readErr
		}
		stanzas, parseErr := parseHistory(data, reader.location)
		if parseErr != nil {
			return nil, fmt.Errorf("parse APT history %s: %w", file.description(), parseErr)
		}
		if update, found, selectErr := newestQualifyingHistory(stanzas); selectErr != nil {
			return nil, fmt.Errorf("select APT history %s: %w", file.description(), selectErr)
		} else if found {
			return update, nil
		}
	}

	return nil, nil
}

// LastUpdate reads APT history through the client's immutable history reader.
func (client *Client) LastUpdate(ctx context.Context) (*packageinfo.LastUpdate, error) {
	if client.history == nil {
		return nil, errors.New("APT history reader is not configured")
	}

	return client.history.LastUpdate(ctx)
}

type historyFile struct {
	path       string
	rotation   int
	compressed bool
}

func (file historyFile) description() string {
	if file.rotation == 0 {
		return "current log"
	}
	if file.compressed {
		return fmt.Sprintf("rotation %d gzip log", file.rotation)
	}

	return fmt.Sprintf("rotation %d log", file.rotation)
}

func (reader *HistoryReader) historyFiles(ctx context.Context) ([]historyFile, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	entries, err := reader.fileSystem.ReadDir(reader.directory)
	if errors.Is(err, fs.ErrNotExist) {
		return make([]historyFile, 0), nil
	}
	if err != nil {
		return nil, &historyAccessError{operation: "list APT history directory", err: err}
	}

	files := make([]historyFile, 0)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rotation, compressed, relevant := parseHistoryFilename(entry.Name())
		if !relevant {
			continue
		}
		if len(files) >= maxHistoryFiles {
			return nil, fmt.Errorf("APT history contains more than %d relevant files", maxHistoryFiles)
		}
		info, infoErr := entry.Info()
		if infoErr != nil {
			return nil, &historyAccessError{operation: "inspect APT history file", err: infoErr}
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("APT history %s is not a regular file", historyFile{rotation: rotation, compressed: compressed}.description())
		}
		files = append(files, historyFile{
			path:       filepath.Join(reader.directory, entry.Name()),
			rotation:   rotation,
			compressed: compressed,
		})
	}

	sort.Slice(files, func(left, right int) bool {
		if files[left].rotation != files[right].rotation {
			return files[left].rotation < files[right].rotation
		}
		if files[left].compressed != files[right].compressed {
			return !files[left].compressed
		}

		return files[left].path < files[right].path
	})

	return files, nil
}

func parseHistoryFilename(name string) (int, bool, bool) {
	if name == historyBaseName {
		return 0, false, true
	}
	if !strings.HasPrefix(name, historyBaseName+".") {
		return 0, false, false
	}

	suffix := strings.TrimPrefix(name, historyBaseName+".")
	compressed := strings.HasSuffix(suffix, ".gz")
	if compressed {
		suffix = strings.TrimSuffix(suffix, ".gz")
	}
	rotation, err := strconv.Atoi(suffix)
	if err != nil || rotation <= 0 {
		return 0, false, false
	}

	return rotation, compressed, true
}

func (reader *HistoryReader) readHistoryFile(file historyFile, remainingBytes *int64) ([]byte, error) {
	opened, err := reader.fileSystem.Open(file.path)
	if err != nil {
		return nil, &historyAccessError{operation: "open APT history " + file.description(), err: err}
	}

	data, readErr := readBoundedHistory(opened, file.compressed)
	closeErr := opened.Close()
	if readErr != nil {
		return nil, fmt.Errorf("read APT history %s: %w", file.description(), readErr)
	}
	if closeErr != nil {
		return nil, &historyAccessError{operation: "close APT history " + file.description(), err: closeErr}
	}
	if int64(len(data)) > *remainingBytes {
		return nil, fmt.Errorf("APT history exceeds %d total bytes", maxHistoryTotalBytes)
	}
	*remainingBytes -= int64(len(data))

	return data, nil
}

func readBoundedHistory(opened io.Reader, compressed bool) ([]byte, error) {
	compressedReader := &io.LimitedReader{R: opened, N: maxHistoryFileBytes + 1}
	var reader io.Reader = compressedReader
	var gzipReader *gzip.Reader
	if compressed {
		var err error
		gzipReader, err = gzip.NewReader(compressedReader)
		if err != nil {
			return nil, errors.New("invalid gzip header")
		}
		reader = gzipReader
	}

	data, err := io.ReadAll(io.LimitReader(reader, maxHistoryFileBytes+1))
	if gzipReader != nil {
		closeErr := gzipReader.Close()
		if err == nil {
			err = closeErr
		}
	}
	if err != nil {
		return nil, errors.New("malformed or unreadable history data")
	}
	if len(data) > maxHistoryFileBytes || compressedReader.N <= 0 {
		return nil, fmt.Errorf("history file exceeds %d bytes", maxHistoryFileBytes)
	}

	return data, nil
}

type historyStanza struct {
	upgrade bool
	start   *time.Time
	end     *time.Time
	failed  bool
}

func parseHistory(data []byte, location *time.Location) ([]historyStanza, error) {
	if location == nil {
		return nil, errors.New("history timezone is required")
	}

	records := make([]map[string]string, 0)
	record := make(map[string]string)
	currentField := ""
	recordBytes := 0
	lineNumber := 0
	flush := func() {
		if len(record) != 0 {
			records = append(records, record)
			record = make(map[string]string)
		}
		currentField = ""
		recordBytes = 0
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), maxHistoryLineBytes)
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.IndexByte(line, 0) >= 0 {
			return nil, fmt.Errorf("malformed history line %d: NUL byte", lineNumber)
		}
		recordBytes += len(line) + 1
		if recordBytes > maxHistoryStanzaBytes {
			return nil, fmt.Errorf("history stanza exceeds %d bytes", maxHistoryStanzaBytes)
		}
		if line == "" {
			flush()
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if currentField == "" {
				return nil, fmt.Errorf("malformed history line %d: orphan continuation", lineNumber)
			}
			record[currentField] += "\n" + strings.TrimSpace(line)
			continue
		}

		separator := strings.IndexByte(line, ':')
		if separator <= 0 || !validDeb822FieldName(line[:separator]) {
			return nil, fmt.Errorf("malformed history line %d: invalid field", lineNumber)
		}
		field := strings.ToLower(line[:separator])
		if _, duplicate := record[field]; duplicate {
			return nil, fmt.Errorf("malformed history stanza: duplicate field %q", field)
		}
		if len(record) >= maxHistoryFields {
			return nil, fmt.Errorf("history stanza has more than %d fields", maxHistoryFields)
		}
		record[field] = strings.TrimSpace(line[separator+1:])
		currentField = field
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("malformed history: line exceeds parser limit")
	}
	flush()

	stanzas := make([]historyStanza, 0, len(records))
	for recordNumber, fields := range records {
		stanza := historyStanza{}
		if upgrade, exists := fields["upgrade"]; exists {
			if strings.TrimSpace(upgrade) == "" {
				return nil, fmt.Errorf("history stanza %d has an empty Upgrade field", recordNumber+1)
			}
			stanza.upgrade = true
		}
		if value, exists := fields["start-date"]; exists {
			parsed, err := parseHistoryTimestamp(value, location)
			if err != nil {
				return nil, fmt.Errorf("history stanza %d has an invalid Start-Date", recordNumber+1)
			}
			stanza.start = &parsed
		}
		if value, exists := fields["end-date"]; exists {
			parsed, err := parseHistoryTimestamp(value, location)
			if err != nil {
				return nil, fmt.Errorf("history stanza %d has an invalid End-Date", recordNumber+1)
			}
			stanza.end = &parsed
		}
		_, stanza.failed = fields["error"]
		stanzas = append(stanzas, stanza)
	}

	return stanzas, nil
}

func parseHistoryTimestamp(value string, location *time.Location) (time.Time, error) {
	fields := strings.Fields(value)
	if len(fields) != 2 {
		return time.Time{}, errors.New("invalid APT history timestamp")
	}
	parsed, err := time.ParseInLocation(historyTimestampLayout, strings.Join(fields, " "), location)
	if err != nil {
		return time.Time{}, errors.New("invalid APT history timestamp")
	}

	return parsed.UTC(), nil
}

func newestQualifyingHistory(stanzas []historyStanza) (*packageinfo.LastUpdate, bool, error) {
	for index := len(stanzas) - 1; index >= 0; index-- {
		stanza := stanzas[index]
		if !stanza.upgrade {
			continue
		}
		if stanza.failed {
			timestamp := stanza.end
			if timestamp == nil {
				timestamp = stanza.start
			}
			if timestamp == nil {
				return nil, false, errors.New("failed Upgrade stanza has no Start-Date or End-Date")
			}

			return &packageinfo.LastUpdate{
				Timestamp: *timestamp,
				Result:    packageinfo.LastUpdateResultFailed,
			}, true, nil
		}
		if stanza.end != nil {
			return &packageinfo.LastUpdate{
				Timestamp: *stanza.end,
				Result:    packageinfo.LastUpdateResultSuccess,
			}, true, nil
		}
		// An Upgrade without End-Date or Error is unfinished. Keep looking.
	}

	return nil, false, nil
}

type historyAccessError struct {
	operation string
	err       error
}

func (failure *historyAccessError) Error() string {
	return failure.operation + " failed"
}

func (failure *historyAccessError) Unwrap() error {
	return failure.err
}
