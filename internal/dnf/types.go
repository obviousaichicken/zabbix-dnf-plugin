package dnf

import (
	"context"
	"fmt"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

// Runner executes DNF commands.
type Runner interface {
	Run(
		ctx context.Context,
		req command.Request,
	) (command.Result, error)
}

// Repository contains an enabled repository's ID and name.
type Repository struct {
	ID   string
	Name string
}

// Update contains package update metadata.
type Update struct {
	Name         string
	Epoch        string
	Version      string
	Release      string
	Arch         string
	RepositoryID string
	Type         UpdateType
}

// UpdateType identifies an advisory category.
type UpdateType uint8

const (
	UpdateTypeOther UpdateType = iota
	UpdateTypeSecurity
	UpdateTypeBugfix
	UpdateTypeEnhancement
)

// LastUpdate describes the most recent completed transaction that upgraded a package.
type LastUpdate struct {
	Timestamp time.Time `json:"timestamp"`
	Result    string    `json:"result"`
}

const (
	LastUpdateResultSuccess     = "success"
	LastUpdateResultFailed      = "failed"
	LastUpdateResultNotRecorded = "not_recorded"
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
