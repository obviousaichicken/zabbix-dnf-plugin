package dnf

import (
	"context"
	"errors"
	"fmt"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

// Runner executes DNF commands.
type Runner interface {
	Run(
		ctx context.Context,
		req command.Request,
	) (command.Result, error)
}

// Repository contains an enabled repository's ID and name.
type Repository = packageinfo.Repository

// Update contains package update metadata.
type Update = packageinfo.Update

// UpdateType identifies an advisory category.
type UpdateType = packageinfo.UpdateType

const (
	UpdateTypeUnknown     = packageinfo.UpdateTypeUnknown
	UpdateTypeSecurity    = packageinfo.UpdateTypeSecurity
	UpdateTypeBugfix      = packageinfo.UpdateTypeBugfix
	UpdateTypeEnhancement = packageinfo.UpdateTypeEnhancement
	UpdateTypeOther       = packageinfo.UpdateTypeOther
)

// LastUpdate describes the most recent completed transaction that upgraded a package.
type LastUpdate = packageinfo.LastUpdate

const (
	LastUpdateResultSuccess     = packageinfo.LastUpdateResultSuccess
	LastUpdateResultFailed      = packageinfo.LastUpdateResultFailed
	LastUpdateResultNotRecorded = packageinfo.LastUpdateResultNotRecorded
)

// CommandError represents a failed DNF command.
type CommandError struct {
	Command    string
	ExitStatus int
	Stderr     string
	Err        error
}

func (e *CommandError) Error() string {
	if e.ExitStatus >= 0 {
		return fmt.Sprintf(
			"dnf command failed with exit status %d: %v",
			e.ExitStatus,
			e.Err,
		)
	}

	return fmt.Sprintf("dnf command failed: %v", e.Err)
}

func (e *CommandError) Unwrap() error {
	return e.Err
}

// Operation returns a bounded, safe DNF command description.
func (e *CommandError) Operation() string {
	return e.Command
}

// Status returns the process exit status, or -1 when no process exited.
func (e *CommandError) Status() int {
	return e.ExitStatus
}

// IsTimeout reports whether command execution exceeded its context deadline.
func (e *CommandError) IsTimeout() bool {
	return errors.Is(e.Err, context.DeadlineExceeded)
}

// IsCanceled reports whether command execution was canceled for another reason.
func (e *CommandError) IsCanceled() bool {
	return errors.Is(e.Err, context.Canceled)
}

var _ command.Failure = (*CommandError)(nil)
