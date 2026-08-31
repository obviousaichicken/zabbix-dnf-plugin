package apt

import (
	"context"
	"errors"
	"io/fs"
	"strings"
	"testing"
)

func TestRebootPendingMarkerSemantics(t *testing.T) {
	t.Parallel()

	permissionErr := errors.New("permission denied")
	tests := []struct {
		name    string
		statErr error
		want    bool
		wantErr error
	}{
		{name: "exists", want: true},
		{name: "missing", statErr: fs.ErrNotExist},
		{name: "permission", statErr: permissionErr, wantErr: permissionErr},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			client := &Client{
				rebootMarker: "/private/alice:s3cr3t/reboot-required",
				stat: func(string) (fs.FileInfo, error) {
					return nil, test.statErr
				},
			}
			got, err := client.RebootPending(context.Background())
			if got != test.want {
				t.Errorf("RebootPending() = %t, want %t", got, test.want)
			}
			if test.wantErr == nil && err != nil {
				t.Fatalf("RebootPending() error = %v", err)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Fatalf("RebootPending() error = %v, want %v", err, test.wantErr)
			}
			if err != nil && strings.Contains(err.Error(), "s3cr3t") {
				t.Errorf("RebootPending() error exposes marker path: %v", err)
			}
		})
	}
}

func TestRebootPendingHonorsCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	statCalled := false
	client := &Client{
		rebootMarker: defaultRebootMarker,
		stat: func(string) (fs.FileInfo, error) {
			statCalled = true
			return nil, nil
		},
	}

	_, err := client.RebootPending(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("RebootPending() error = %v, want context canceled", err)
	}
	if statCalled {
		t.Error("reboot marker was statted after cancellation")
	}
}
