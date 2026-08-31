package dnf

import (
	"strings"
	"time"
)

// AdvisorySeverity is the normalized vendor severity of a DNF security advisory.
type AdvisorySeverity uint8

const (
	AdvisorySeverityUnknown AdvisorySeverity = iota
	AdvisorySeverityLow
	AdvisorySeverityModerate
	AdvisorySeverityImportant
	AdvisorySeverityCritical
)

// ParseAdvisorySeverity normalizes a vendor severity. Unknown spellings are
// representable data and therefore map to Unknown rather than failing parsing.
func ParseAdvisorySeverity(value string) AdvisorySeverity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "low":
		return AdvisorySeverityLow
	case "moderate", "medium":
		return AdvisorySeverityModerate
	case "important", "high":
		return AdvisorySeverityImportant
	case "critical":
		return AdvisorySeverityCritical
	default:
		return AdvisorySeverityUnknown
	}
}

// String returns the public severity spelling.
func (s AdvisorySeverity) String() string {
	switch s {
	case AdvisorySeverityLow:
		return "low"
	case AdvisorySeverityModerate:
		return "moderate"
	case AdvisorySeverityImportant:
		return "important"
	case AdvisorySeverityCritical:
		return "critical"
	case AdvisorySeverityUnknown:
		return "unknown"
	default:
		return "unknown"
	}
}

// Valid reports whether the value is a defined severity, including Unknown.
func (s AdvisorySeverity) Valid() bool {
	return s <= AdvisorySeverityCritical
}

// AdvisoryReference is one vendor-supplied advisory reference.
type AdvisoryReference struct {
	Type  string
	ID    string
	Title string
	URL   string
}

// Advisory contains one applicable DNF security advisory.
type Advisory struct {
	ID              string
	Type            string
	Severity        AdvisorySeverity
	Title           string
	IssuedAt        *time.Time
	UpdatedAt       *time.Time
	CVEIDs          []string
	References      []AdvisoryReference
	AffectedUpdates []NEVRA
}

// AdvisoryCapabilities records whether optional advisory metadata is complete.
type AdvisoryCapabilities struct {
	DetailsComplete    bool
	CVEsComplete       bool
	IssueDatesComplete bool
}

// AdvisoryData is one complete, immutable advisory-collection result.
type AdvisoryData struct {
	CollectedAt  time.Time
	Capabilities AdvisoryCapabilities
	Advisories   []Advisory
}
