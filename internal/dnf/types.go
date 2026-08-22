package dnf

import (
	"context"
	"fmt"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

// Runner executes a DNF command.
type Runner interface {
	Run(
		ctx context.Context,
		req command.Request,
	) (command.Result, error)
}

// Repository is an enabled package repository.
type Repository struct {
	ID   string
	Name string
}

// Update is an available package update.
type Update struct {
	Name         string
	Epoch        string
	Version      string
	Release      string
	Arch         string
	RepositoryID string
	Type         UpdateType
}

// UpdateType identifies the advisory category associated with an update.
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

// CommandError describes a failed DNF command.
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
