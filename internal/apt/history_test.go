package apt

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

func TestHistoryReaderCompletedTransactionRules(t *testing.T) {
	t.Parallel()

	location := time.FixedZone("CEST", 2*60*60)
	tests := []struct {
		name       string
		history    string
		wantResult string
		wantTime   time.Time
	}{
		{
			name: "successful Upgrade uses End-Date",
			history: `Start-Date: 2026-08-30  09:00:00
Upgrade: pkg:amd64 (1.0, 2.0)
End-Date: 2026-08-30  09:01:30
`,
			wantResult: packageinfo.LastUpdateResultSuccess,
			wantTime:   time.Date(2026, time.August, 30, 7, 1, 30, 0, time.UTC),
		},
		{
			name: "failed Upgrade prefers End-Date",
			history: `Start-Date: 2026-08-30  09:00:00
Upgrade: pkg:amd64 (1.0, 2.0)
Error: dpkg returned an error
End-Date: 2026-08-30  09:02:00
`,
			wantResult: packageinfo.LastUpdateResultFailed,
			wantTime:   time.Date(2026, time.August, 30, 7, 2, 0, 0, time.UTC),
		},
		{
			name: "failed Upgrade falls back to Start-Date",
			history: `Start-Date: 2026-08-30  09:00:00
Upgrade: pkg:amd64 (1.0, 2.0)
Error: interrupted
`,
			wantResult: packageinfo.LastUpdateResultFailed,
			wantTime:   time.Date(2026, time.August, 30, 7, 0, 0, 0, time.UTC),
		},
		{
			name: "newer unfinished Upgrade is ignored",
			history: `Start-Date: 2026-08-29  10:00:00
Upgrade: older:amd64 (1.0, 2.0)
End-Date: 2026-08-29  10:05:00

Start-Date: 2026-08-30  11:00:00
Upgrade: unfinished:amd64 (1.0, 2.0)
`,
			wantResult: packageinfo.LastUpdateResultSuccess,
			wantTime:   time.Date(2026, time.August, 29, 8, 5, 0, 0, time.UTC),
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			writeHistoryFile(t, directory, historyBaseName, []byte(test.history), false)
			reader := mustHistoryReader(t, osHistoryFileSystem{}, directory, location)

			update, err := reader.LastUpdate(context.Background())
			if err != nil {
				t.Fatalf("LastUpdate() error = %v", err)
			}
			if update == nil || update.Result != test.wantResult || !update.Timestamp.Equal(test.wantTime) {
				t.Fatalf("LastUpdate() = %#v, want %s at %s", update, test.wantResult, test.wantTime)
			}
		})
	}
}

func TestHistoryReaderSearchesRotationsNewestFirst(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeHistoryFile(t, directory, historyBaseName, []byte(`Start-Date: 2026-08-31  12:00:00
Upgrade: unfinished:amd64 (1.0, 2.0)
`), false)
	writeHistoryFile(t, directory, historyBaseName+".1", []byte(successHistory("2026-08-30 10:00:00")), false)
	writeHistoryFile(t, directory, historyBaseName+".1.gz", []byte(successHistory("2026-08-29 10:00:00")), true)
	writeHistoryFile(t, directory, historyBaseName+".2.gz", []byte(successHistory("2026-08-28 10:00:00")), true)
	if err := os.WriteFile(filepath.Join(directory, "term.log"), []byte("ignored"), 0o600); err != nil {
		t.Fatalf("write unrelated log: %v", err)
	}
	reader := mustHistoryReader(t, osHistoryFileSystem{}, directory, time.UTC)

	update, err := reader.LastUpdate(context.Background())
	if err != nil {
		t.Fatalf("LastUpdate() error = %v", err)
	}
	want := time.Date(2026, time.August, 30, 10, 0, 0, 0, time.UTC)
	if update == nil || !update.Timestamp.Equal(want) {
		t.Fatalf("LastUpdate() = %#v, want uncompressed rotation 1 at %s", update, want)
	}
}

func TestHistoryReaderReadsGzipRotation(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	writeHistoryFile(t, directory, historyBaseName+".2.gz", []byte(successHistory("2026-08-28 10:00:00")), true)
	reader := mustHistoryReader(t, osHistoryFileSystem{}, directory, time.UTC)

	update, err := reader.LastUpdate(context.Background())
	if err != nil {
		t.Fatalf("LastUpdate() error = %v", err)
	}
	if update == nil || update.Result != packageinfo.LastUpdateResultSuccess {
		t.Fatalf("LastUpdate() = %#v, want gzip success", update)
	}
}

func TestHistoryReaderReturnsNotRecorded(t *testing.T) {
	t.Parallel()

	t.Run("missing directory", func(t *testing.T) {
		t.Parallel()

		reader := mustHistoryReader(
			t,
			osHistoryFileSystem{},
			filepath.Join(t.TempDir(), "missing"),
			time.UTC,
		)
		update, err := reader.LastUpdate(context.Background())
		if err != nil || update != nil {
			t.Fatalf("LastUpdate() = %#v, %v; want not recorded", update, err)
		}
	})

	t.Run("no qualifying transaction", func(t *testing.T) {
		t.Parallel()

		directory := t.TempDir()
		writeHistoryFile(t, directory, historyBaseName, []byte(`Start-Date: 2026-08-30  09:00:00
Install: new-pkg:amd64 (1.0)
End-Date: 2026-08-30  09:01:00
`), false)
		reader := mustHistoryReader(t, osHistoryFileSystem{}, directory, time.UTC)
		update, err := reader.LastUpdate(context.Background())
		if err != nil || update != nil {
			t.Fatalf("LastUpdate() = %#v, %v; want not recorded", update, err)
		}
	})
}

func TestHistoryReaderRejectsMalformedExistingLogs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		content []byte
		gzip    bool
		want    string
	}{
		{name: "invalid field", content: []byte("not a field\n"), want: "invalid field"},
		{
			name:    "duplicate field",
			content: []byte("Start-Date: 2026-08-30  09:00:00\nStart-Date: 2026-08-30  10:00:00\n"),
			want:    "duplicate field",
		},
		{
			name:    "invalid timestamp",
			content: []byte("Start-Date: yesterday\nUpgrade: pkg (1, 2)\nError: failed\n"),
			want:    "invalid Start-Date",
		},
		{
			name:    "failed without timestamp",
			content: []byte("Upgrade: pkg (1, 2)\nError: failed\n"),
			want:    "no Start-Date or End-Date",
		},
		{name: "invalid gzip", content: []byte("not gzip"), gzip: true, want: "invalid gzip header"},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			name := historyBaseName
			if test.gzip {
				name += ".1.gz"
				if err := os.WriteFile(filepath.Join(directory, name), test.content, 0o600); err != nil {
					t.Fatalf("write invalid gzip: %v", err)
				}
			} else {
				writeHistoryFile(t, directory, name, test.content, false)
			}
			reader := mustHistoryReader(t, osHistoryFileSystem{}, directory, time.UTC)
			_, err := reader.LastUpdate(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LastUpdate() error = %v, want substring %q", err, test.want)
			}
		})
	}
}

func TestHistoryReaderRejectsOversizeReads(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		content    []byte
		compressed bool
	}{
		{name: "plain", content: bytes.Repeat([]byte{'x'}, maxHistoryFileBytes+1)},
		{name: "gzip expansion", content: bytes.Repeat([]byte{'x'}, maxHistoryFileBytes+1), compressed: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			name := historyBaseName
			if test.compressed {
				name += ".1.gz"
			}
			writeHistoryFile(t, directory, name, test.content, test.compressed)
			reader := mustHistoryReader(t, osHistoryFileSystem{}, directory, time.UTC)
			_, err := reader.LastUpdate(context.Background())
			if err == nil || !strings.Contains(err.Error(), "exceeds") {
				t.Fatalf("LastUpdate() error = %v, want size failure", err)
			}
		})
	}
}

func TestHistoryReaderRejectsUnreadableFilesSafely(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("open /private/alice:s3cr3t/history.log: permission denied")
	fileSystem := &fakeHistoryFileSystem{
		entries: []fs.DirEntry{fakeHistoryDirEntry{name: historyBaseName, mode: 0o600}},
		openErr: sentinel,
	}
	reader := mustHistoryReader(t, fileSystem, "/private/alice:s3cr3t", time.UTC)

	_, err := reader.LastUpdate(context.Background())
	if !errors.Is(err, sentinel) {
		t.Fatalf("LastUpdate() error = %v, want sentinel", err)
	}
	for _, secret := range []string{"alice", "s3cr3t", "/private/"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("LastUpdate() error exposes path detail %q: %v", secret, err)
		}
	}
}

func TestHistoryReaderHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	fileSystem := &fakeHistoryFileSystem{}
	reader := mustHistoryReader(t, fileSystem, "/var/log/apt", time.UTC)

	_, err := reader.LastUpdate(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("LastUpdate() error = %v, want context canceled", err)
	}
	if fileSystem.readDirCalls != 0 {
		t.Error("history directory was read after cancellation")
	}
}

func TestHistoryReaderBoundsRelevantFiles(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	for rotation := 1; rotation <= maxHistoryFiles+1; rotation++ {
		writeHistoryFile(t, directory, historyBaseName+"."+strconv.Itoa(rotation), nil, false)
	}
	reader := mustHistoryReader(t, osHistoryFileSystem{}, directory, time.UTC)

	_, err := reader.LastUpdate(context.Background())
	if err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("LastUpdate() error = %v, want relevant-file bound", err)
	}
}

func TestNewHistoryReaderValidatesDependencies(t *testing.T) {
	t.Parallel()

	if _, err := newHistoryReaderForTest(nil, "/var/log/apt", time.UTC); err == nil {
		t.Error("nil history filesystem was accepted")
	}
	if _, err := newHistoryReaderForTest(osHistoryFileSystem{}, "relative", time.UTC); err == nil {
		t.Error("relative history directory was accepted")
	}
	if _, err := newHistoryReaderForTest(osHistoryFileSystem{}, "/var/log/apt", nil); err == nil {
		t.Error("nil history timezone was accepted")
	}
}

func FuzzHistoryContract(f *testing.F) {
	f.Add(`Start-Date: 2026-08-30  09:00:00
Upgrade: pkg:amd64 (1.0, 2.0)
End-Date: 2026-08-30  09:01:30
`)
	f.Add(`Start-Date: 2026-08-30  09:00:00
Upgrade: pkg:amd64 (1.0, 2.0)
Error: failed
`)

	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > maxHistoryFileBytes {
			t.Skip()
		}
		stanzas, err := parseHistory([]byte(input), time.UTC)
		if err == nil {
			_, _, _ = newestQualifyingHistory(stanzas)
		}
	})
}

type fakeHistoryFileSystem struct {
	entries      []fs.DirEntry
	files        map[string][]byte
	readDirErr   error
	openErr      error
	readDirCalls int
}

func (fileSystem *fakeHistoryFileSystem) ReadDir(string) ([]fs.DirEntry, error) {
	fileSystem.readDirCalls++
	return fileSystem.entries, fileSystem.readDirErr
}

func (fileSystem *fakeHistoryFileSystem) Open(name string) (io.ReadCloser, error) {
	if fileSystem.openErr != nil {
		return nil, fileSystem.openErr
	}

	return io.NopCloser(bytes.NewReader(fileSystem.files[name])), nil
}

type fakeHistoryDirEntry struct {
	name    string
	mode    fs.FileMode
	infoErr error
}

func (entry fakeHistoryDirEntry) Name() string      { return entry.name }
func (entry fakeHistoryDirEntry) IsDir() bool       { return entry.mode.IsDir() }
func (entry fakeHistoryDirEntry) Type() fs.FileMode { return entry.mode.Type() }
func (entry fakeHistoryDirEntry) Info() (fs.FileInfo, error) {
	return fakeFileInfo{mode: entry.mode, modified: time.Now()}, entry.infoErr
}

func mustHistoryReader(
	t *testing.T,
	fileSystem historyFileSystem,
	directory string,
	location *time.Location,
) *HistoryReader {
	t.Helper()

	reader, err := newHistoryReaderForTest(fileSystem, directory, location)
	if err != nil {
		t.Fatalf("construct history reader: %v", err)
	}

	return reader
}

func writeHistoryFile(t *testing.T, directory, name string, content []byte, compressed bool) {
	t.Helper()

	path := filepath.Join(directory, name)
	if !compressed {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatalf("write history file: %v", err)
		}

		return
	}

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("create gzip history: %v", err)
	}
	writer := gzip.NewWriter(file)
	if _, err := writer.Write(content); err != nil {
		_ = writer.Close()
		_ = file.Close()
		t.Fatalf("write gzip history: %v", err)
	}
	if err := writer.Close(); err != nil {
		_ = file.Close()
		t.Fatalf("close gzip writer: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("close gzip history: %v", err)
	}
}

func successHistory(timestamp string) string {
	return "Start-Date: " + timestamp + "\n" +
		"Upgrade: pkg:amd64 (1.0, 2.0)\n" +
		"End-Date: " + timestamp + "\n"
}
