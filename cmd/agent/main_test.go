package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/results"
)

func TestRunDispatchesMode(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		args      []string
		wantTest  int
		wantAgent int
	}{
		{name: "test mode", args: []string{testArg}, wantTest: 1},
		{name: "agent socket", args: []string{"/run/zabbix/plugin.sock"}, wantAgent: 1},
		{name: "no arguments", wantAgent: 1},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()

			testCalls := 0
			agentCalls := 0
			err := run(
				testCase.args,
				func() error {
					testCalls++
					return nil
				},
				func() error {
					agentCalls++
					return nil
				},
			)
			if err != nil {
				t.Fatalf("run() error = %v, want nil", err)
			}
			if testCalls != testCase.wantTest {
				t.Errorf("test mode calls = %d, want %d", testCalls, testCase.wantTest)
			}
			if agentCalls != testCase.wantAgent {
				t.Errorf("agent mode calls = %d, want %d", agentCalls, testCase.wantAgent)
			}
		})
	}
}

func TestRunRejectsTestArguments(t *testing.T) {
	t.Parallel()

	called := false
	err := run(
		[]string{testArg, "unexpected"},
		func() error {
			called = true

			return nil
		},
		func() error {
			called = true

			return nil
		},
	)
	if err == nil {
		t.Fatal("run() error = nil, want an argument error")
	}
	if called {
		t.Fatal("run() called a mode after rejecting arguments")
	}

	const want = "--test does not accept arguments"
	if err.Error() != want {
		t.Fatalf("run() error = %q, want %q", err, want)
	}
}

func TestCollectAndWrite(t *testing.T) {
	t.Parallel()

	want := results.Payload{
		Collection: results.Collection{Complete: true, DurationMS: -1},
		Summary:    results.Summary{Repositories: 2},
	}
	var output bytes.Buffer

	err := collectAndWrite(
		t.Context(),
		&output,
		func(ctx context.Context) (results.Payload, error) {
			deadline, ok := ctx.Deadline()
			if !ok {
				t.Fatal("collection context has no deadline")
			}

			remaining := time.Until(deadline)
			if remaining <= collectionTimeout-time.Second || remaining > collectionTimeout {
				t.Fatalf("collection deadline remaining = %s, want approximately %s", remaining, collectionTimeout)
			}

			return want, nil
		},
	)
	if err != nil {
		t.Fatalf("collectAndWrite() error = %v, want nil", err)
	}
	if !strings.Contains(output.String(), "\n  \"collection\"") {
		t.Fatalf("collectAndWrite() output is not indented JSON: %q", output.String())
	}

	var got results.Payload
	if err := json.Unmarshal(output.Bytes(), &got); err != nil {
		t.Fatalf("decode output: %v", err)
	}
	if !got.Collection.Complete || got.Summary.Repositories != 2 {
		t.Fatalf("decoded payload = %#v, want collection complete with 2 repositories", got)
	}
	if got.Collection.DurationMS < 0 {
		t.Fatalf("collection duration = %d, want non-negative", got.Collection.DurationMS)
	}
}

func TestCollectAndWriteReturnsCollectionError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("collection failed")
	var output bytes.Buffer

	err := collectAndWrite(
		t.Context(),
		&output,
		func(context.Context) (results.Payload, error) {
			return results.Payload{}, wantErr
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("collectAndWrite() error = %v, want %v", err, wantErr)
	}
	if output.Len() != 0 {
		t.Fatalf("collectAndWrite() output = %q, want empty", output.String())
	}
}

func TestCollectAndWriteReturnsWriterError(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("write failed")
	err := collectAndWrite(
		t.Context(),
		errorWriter{err: wantErr},
		func(context.Context) (results.Payload, error) {
			return results.Payload{}, nil
		},
	)
	if !errors.Is(err, wantErr) {
		t.Fatalf("collectAndWrite() error = %v, want %v", err, wantErr)
	}
}

func TestCollectAndWritePropagatesParentCancellation(t *testing.T) {
	t.Parallel()

	parent, cancel := context.WithCancel(t.Context())
	cancel()

	err := collectAndWrite(
		parent,
		io.Discard,
		func(ctx context.Context) (results.Payload, error) {
			<-ctx.Done()

			return results.Payload{}, ctx.Err()
		},
	)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("collectAndWrite() error = %v, want context canceled", err)
	}
}

func TestExecuteAgentHandlerShutsDownOnCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	executeDone := make(chan struct{})
	shutdownCalled := false
	cancel()

	err := executeAgentHandler(
		ctx,
		func() error {
			<-executeDone

			return nil
		},
		func() {
			shutdownCalled = true
			close(executeDone)
		},
	)
	if err != nil {
		t.Fatalf("executeAgentHandler() error = %v, want nil", err)
	}
	if !shutdownCalled {
		t.Fatal("executeAgentHandler() did not shut down after cancellation")
	}
}

type errorWriter struct {
	err error
}

func (w errorWriter) Write([]byte) (int, error) {
	return 0, w.err
}
