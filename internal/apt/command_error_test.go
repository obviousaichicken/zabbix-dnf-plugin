package apt

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

func TestCommandErrorImplementsSafeFailure(t *testing.T) {
	t.Parallel()

	cause := context.DeadlineExceeded
	failure := &CommandError{
		operation:  "apt-cache policy (512 packages)",
		exitStatus: -1,
		err:        cause,
	}
	if !errors.Is(failure, cause) || !failure.IsTimeout() || failure.IsCanceled() {
		t.Errorf("CommandError flags = timeout:%t canceled:%t", failure.IsTimeout(), failure.IsCanceled())
	}
	if failure.Status() != -1 || failure.Operation() != "apt-cache policy (512 packages)" {
		t.Errorf("CommandError metadata = %d/%q", failure.Status(), failure.Operation())
	}
	if strings.Contains(failure.Operation(), "https://") {
		t.Errorf("CommandError operation exposes arguments: %q", failure.Operation())
	}

	var structured command.Failure = failure
	if structured == nil {
		t.Fatal("CommandError does not implement command.Failure")
	}
}
