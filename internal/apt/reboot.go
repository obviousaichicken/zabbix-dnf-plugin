package apt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
)

const defaultRebootMarker = "/run/reboot-required"

// RebootPending reports only the presence of /run/reboot-required.
func (client *Client) RebootPending(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	_, err := client.stat(client.rebootMarker)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	return false, &markerStatError{err: err}
}

type markerStatError struct {
	err error
}

func (*markerStatError) Error() string {
	return fmt.Sprintf("failed to stat APT reboot marker %q", defaultRebootMarker)
}

func (failure *markerStatError) Unwrap() error {
	return failure.err
}
