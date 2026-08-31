// Package packageinfo defines the package-manager-neutral update snapshot.
package packageinfo

import (
	"errors"
	"fmt"
	"time"
)

// Backend identifies the package manager that produced a snapshot.
type Backend uint8

const (
	BackendUnknown Backend = iota
	BackendDNF
	BackendAPT
)

// String returns the public backend name.
func (b Backend) String() string {
	switch b {
	case BackendDNF:
		return "dnf"
	case BackendAPT:
		return "apt"
	case BackendUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// Valid reports whether the backend is a supported, known value.
func (b Backend) Valid() bool {
	return b == BackendDNF || b == BackendAPT
}

// Capability describes the fidelity of one backend feature.
type Capability uint8

const (
	CapabilityUnknown Capability = iota
	CapabilitySupported
	CapabilityBestEffort
	CapabilityUnsupported
)

// String returns the public capability value.
func (c Capability) String() string {
	switch c {
	case CapabilitySupported:
		return "supported"
	case CapabilityBestEffort:
		return "best_effort"
	case CapabilityUnsupported:
		return "unsupported"
	case CapabilityUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// Valid reports whether the capability is explicitly known.
func (c Capability) Valid() bool {
	return c == CapabilitySupported ||
		c == CapabilityBestEffort ||
		c == CapabilityUnsupported
}

// ClassificationCapabilities describes update-type support.
type ClassificationCapabilities struct {
	Security    Capability
	Bugfix      Capability
	Enhancement Capability
	Other       Capability
}

// Capabilities records the fidelity of every generic snapshot feature.
type Capabilities struct {
	Classification        ClassificationCapabilities
	RepositoryAttribution Capability
	RebootDetection       Capability
	LastUpdate            Capability
	MetadataAge           Capability
}

// Validate rejects an omitted or unknown capability.
func (c Capabilities) Validate() error {
	values := []struct {
		name  string
		value Capability
	}{
		{"classification.security", c.Classification.Security},
		{"classification.bugfix", c.Classification.Bugfix},
		{"classification.enhancement", c.Classification.Enhancement},
		{"classification.other", c.Classification.Other},
		{"repository_attribution", c.RepositoryAttribution},
		{"reboot_detection", c.RebootDetection},
		{"last_update", c.LastUpdate},
		{"metadata_age", c.MetadataAge},
	}
	for _, candidate := range values {
		if !candidate.value.Valid() {
			return fmt.Errorf("unknown capability %s", candidate.name)
		}
	}

	return nil
}

// Repository contains a logical package repository.
type Repository struct {
	ID   string
	Name string
}

// UpdateType identifies a package update classification.
type UpdateType uint8

const (
	UpdateTypeUnknown UpdateType = iota
	UpdateTypeSecurity
	UpdateTypeBugfix
	UpdateTypeEnhancement
	UpdateTypeOther
)

// String returns the public update classification.
func (u UpdateType) String() string {
	switch u {
	case UpdateTypeSecurity:
		return "security"
	case UpdateTypeBugfix:
		return "bugfix"
	case UpdateTypeEnhancement:
		return "enhancement"
	case UpdateTypeOther:
		return "other"
	case UpdateTypeUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// Valid reports whether the update type is explicitly known.
func (u UpdateType) Valid() bool {
	return u >= UpdateTypeSecurity && u <= UpdateTypeOther
}

// Update contains package update metadata shared by DNF and APT.
type Update struct {
	Name         string
	Epoch        string
	Version      string
	Release      string
	Arch         string
	RepositoryID string
	Type         UpdateType
	FullVersion  string
	Identifier   string
}

// LastUpdate describes the most recent completed package-upgrade transaction.
type LastUpdate struct {
	Timestamp time.Time `json:"timestamp"`
	Result    string    `json:"result"`
}

const (
	LastUpdateResultSuccess     = "success"
	LastUpdateResultFailed      = "failed"
	LastUpdateResultNotRecorded = "not_recorded"
)

// Metadata describes the oldest package index participating in collection.
type Metadata struct {
	RefreshedAt *time.Time
	AgeSeconds  *int64
}

// Snapshot is one complete, uncached package collection.
type Snapshot struct {
	Backend       Backend
	Capabilities  Capabilities
	Metadata      Metadata
	Repositories  []Repository
	Updates       []Update
	RebootPending bool
	LastUpdate    *LastUpdate
}

// ValidateBasic rejects unknown enums and broken repository references.
func (s Snapshot) ValidateBasic() error {
	if !s.Backend.Valid() {
		return errors.New("unknown package backend")
	}
	if err := s.Capabilities.Validate(); err != nil {
		return fmt.Errorf("validate capabilities: %w", err)
	}

	repositories := make(map[string]struct{}, len(s.Repositories))
	for _, repository := range s.Repositories {
		if repository.ID == "" {
			return errors.New("repository ID is required")
		}
		if _, exists := repositories[repository.ID]; exists {
			return fmt.Errorf("duplicate repository ID %q", repository.ID)
		}
		repositories[repository.ID] = struct{}{}
	}

	for _, update := range s.Updates {
		if !update.Type.Valid() {
			return fmt.Errorf("update %q has unknown classification", update.Name)
		}
		if _, exists := repositories[update.RepositoryID]; !exists {
			return fmt.Errorf(
				"update %q references unknown repository %q",
				update.Name,
				update.RepositoryID,
			)
		}
	}

	return nil
}
