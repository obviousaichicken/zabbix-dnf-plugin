package results

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

const PackageSchemaVersion = 1

// PackagePayload is the package-manager-neutral packages.get response.
type PackagePayload struct {
	SchemaVersion  int                 `json:"schema_version"` //nolint:tagliatelle // Public schema uses snake_case.
	Backend        string              `json:"backend"`
	Capabilities   PackageCapabilities `json:"capabilities"`
	Metadata       PackageMetadata     `json:"metadata"`
	Collection     Collection          `json:"collection"`
	Classification Classification      `json:"classification"`
	Summary        Summary             `json:"summary"`
	Repositories   []Repository        `json:"repositories"`
	Updates        []PackageUpdate     `json:"updates"`
}

// PackageCapabilities serializes generic backend fidelity.
type PackageCapabilities struct {
	Classification        PackageClassificationCapabilities `json:"classification"`
	RepositoryAttribution string                            `json:"repository_attribution"` //nolint:tagliatelle // Public schema uses snake_case.
	RebootDetection       string                            `json:"reboot_detection"`       //nolint:tagliatelle // Public schema uses snake_case.
	LastUpdate            string                            `json:"last_update"`            //nolint:tagliatelle // Public schema uses snake_case.
	MetadataAge           string                            `json:"metadata_age"`           //nolint:tagliatelle // Public schema uses snake_case.
}

// PackageClassificationCapabilities serializes classification fidelity.
type PackageClassificationCapabilities struct {
	Security    string `json:"security"`
	Bugfix      string `json:"bugfix"`
	Enhancement string `json:"enhancement"`
	Other       string `json:"other"`
}

// PackageMetadata describes the oldest participating package index.
type PackageMetadata struct {
	RefreshedAt *time.Time `json:"refreshed_at"` //nolint:tagliatelle // Public schema uses snake_case.
	AgeSeconds  *int64     `json:"age_seconds"`  //nolint:tagliatelle // Public schema uses snake_case.
}

// PackageUpdate contains generic update details.
type PackageUpdate struct {
	RepositoryID string `json:"repository_id"` //nolint:tagliatelle // Public schema uses snake_case.
	Name         string `json:"name"`
	Epoch        string `json:"epoch"`
	Version      string `json:"version"`
	Release      string `json:"release"`
	Arch         string `json:"arch"`
	Type         string `json:"type"`
	FullVersion  string `json:"full_version"` //nolint:tagliatelle // Public schema uses snake_case.
	Identifier   string `json:"identifier"`
}

// BuildPackages validates and builds a deterministic packages.get payload.
//
//nolint:funlen,cyclop // Schema validation is intentionally centralized at this trust boundary.
func BuildPackages(snapshot packageinfo.Snapshot) (PackagePayload, error) {
	if err := validatePackageSnapshot(snapshot); err != nil {
		return PackagePayload{}, err
	}

	payload := PackagePayload{
		SchemaVersion: PackageSchemaVersion,
		Backend:       snapshot.Backend.String(),
		Capabilities:  newPackageCapabilities(snapshot.Capabilities),
		Metadata: PackageMetadata{
			RefreshedAt: snapshot.Metadata.RefreshedAt,
			AgeSeconds:  snapshot.Metadata.AgeSeconds,
		},
		Collection: Collection{Complete: true},
		Classification: Classification{
			Complete:         true,
			FailedCategories: make([]string, 0),
		},
		Summary: Summary{
			Repositories:   len(snapshot.Repositories),
			Updates:        len(snapshot.Updates),
			UpdatesPending: len(snapshot.Updates) > 0,
			RebootPending:  snapshot.RebootPending,
			UpdateTypes:    countPackageUpdateTypes(snapshot.Updates),
			LastUpdate:     NewLastUpdate(snapshot.LastUpdate),
		},
		Repositories: make([]Repository, 0, len(snapshot.Repositories)),
		Updates:      make([]PackageUpdate, 0, len(snapshot.Updates)),
	}

	updateCounts := make(map[string]int, len(snapshot.Repositories))
	for _, repository := range snapshot.Repositories {
		payload.Repositories = append(payload.Repositories, Repository{
			ID:   repository.ID,
			Name: repository.Name,
		})
	}
	for _, update := range snapshot.Updates {
		updateCounts[update.RepositoryID]++
		payload.Updates = append(payload.Updates, PackageUpdate{
			RepositoryID: update.RepositoryID,
			Name:         update.Name,
			Epoch:        update.Epoch,
			Version:      update.Version,
			Release:      update.Release,
			Arch:         update.Arch,
			Type:         update.Type.String(),
			FullVersion:  update.FullVersion,
			Identifier:   update.Identifier,
		})
	}
	for index := range payload.Repositories {
		payload.Repositories[index].UpdateCount = updateCounts[payload.Repositories[index].ID]
	}

	sort.Slice(payload.Repositories, func(i, j int) bool {
		return payload.Repositories[i].ID < payload.Repositories[j].ID
	})
	sort.Slice(payload.Updates, func(i, j int) bool {
		left := payload.Updates[i]
		right := payload.Updates[j]
		if left.RepositoryID != right.RepositoryID {
			return left.RepositoryID < right.RepositoryID
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Arch < right.Arch
	})

	return payload, nil
}

func validatePackageSnapshot(snapshot packageinfo.Snapshot) error {
	if err := snapshot.ValidateBasic(); err != nil {
		return fmt.Errorf("invalid package snapshot: %w", err)
	}
	if err := validateBackendCapabilities(snapshot); err != nil {
		return err
	}
	if err := validatePackageMetadata(snapshot); err != nil {
		return err
	}
	if snapshot.LastUpdate != nil {
		if snapshot.LastUpdate.Timestamp.IsZero() {
			return errors.New("last update timestamp is required")
		}
		if snapshot.LastUpdate.Result != packageinfo.LastUpdateResultSuccess &&
			snapshot.LastUpdate.Result != packageinfo.LastUpdateResultFailed {
			return fmt.Errorf("invalid last update result %q", snapshot.LastUpdate.Result)
		}
	}

	seenAPTUpdates := make(map[string]struct{}, len(snapshot.Updates))
	for _, update := range snapshot.Updates {
		if update.Name == "" || update.Arch == "" || update.Version == "" {
			return fmt.Errorf("update %q has incomplete package identity", update.Name)
		}
		if snapshot.Backend == packageinfo.BackendDNF && update.Release == "" {
			return fmt.Errorf("DNF update %q has no release", update.Name)
		}
		if update.FullVersion != packageinfo.FullVersion(update) {
			return fmt.Errorf("update %q has inconsistent full version", update.Name)
		}
		if update.Identifier != packageinfo.Identifier(snapshot.Backend, update) {
			return fmt.Errorf("update %q has inconsistent identifier", update.Name)
		}

		capability := classificationCapability(snapshot.Capabilities.Classification, update.Type)
		if capability == packageinfo.CapabilityUnsupported {
			return fmt.Errorf("update %q uses unsupported classification %s", update.Name, update.Type)
		}

		if snapshot.Backend == packageinfo.BackendAPT {
			key := update.Name + "\x00" + update.Arch
			if _, exists := seenAPTUpdates[key]; exists {
				return fmt.Errorf("duplicate APT update %s:%s", update.Name, update.Arch)
			}
			seenAPTUpdates[key] = struct{}{}
		}
	}

	return nil
}

func validateBackendCapabilities(snapshot packageinfo.Snapshot) error {
	capabilities := snapshot.Capabilities
	if capabilities.RepositoryAttribution != packageinfo.CapabilitySupported ||
		capabilities.RebootDetection != packageinfo.CapabilitySupported {
		return errors.New("repository attribution and reboot detection must be supported")
	}

	switch snapshot.Backend {
	case packageinfo.BackendDNF:
		if capabilities.Classification.Security != packageinfo.CapabilitySupported ||
			capabilities.Classification.Bugfix != packageinfo.CapabilitySupported ||
			capabilities.Classification.Enhancement != packageinfo.CapabilitySupported ||
			capabilities.Classification.Other != packageinfo.CapabilitySupported ||
			capabilities.LastUpdate != packageinfo.CapabilitySupported ||
			capabilities.MetadataAge != packageinfo.CapabilityUnsupported {
			return errors.New("invalid DNF capability combination")
		}
	case packageinfo.BackendAPT:
		if capabilities.Classification.Security != packageinfo.CapabilitySupported ||
			capabilities.Classification.Bugfix != packageinfo.CapabilityUnsupported ||
			capabilities.Classification.Enhancement != packageinfo.CapabilityUnsupported ||
			capabilities.Classification.Other != packageinfo.CapabilitySupported ||
			capabilities.LastUpdate != packageinfo.CapabilityBestEffort ||
			capabilities.MetadataAge != packageinfo.CapabilitySupported {
			return errors.New("invalid APT capability combination")
		}
	case packageinfo.BackendUnknown:
		return errors.New("unknown package backend")
	}

	return nil
}

func validatePackageMetadata(snapshot packageinfo.Snapshot) error {
	refreshedAt := snapshot.Metadata.RefreshedAt
	ageSeconds := snapshot.Metadata.AgeSeconds
	if snapshot.Capabilities.MetadataAge == packageinfo.CapabilityUnsupported {
		if refreshedAt != nil || ageSeconds != nil {
			return errors.New("metadata age fields present when unsupported")
		}

		return nil
	}
	if refreshedAt == nil || refreshedAt.IsZero() || ageSeconds == nil || *ageSeconds < 0 {
		return errors.New("supported metadata age is incomplete")
	}

	return nil
}

func classificationCapability(
	capabilities packageinfo.ClassificationCapabilities,
	updateType packageinfo.UpdateType,
) packageinfo.Capability {
	switch updateType {
	case packageinfo.UpdateTypeSecurity:
		return capabilities.Security
	case packageinfo.UpdateTypeBugfix:
		return capabilities.Bugfix
	case packageinfo.UpdateTypeEnhancement:
		return capabilities.Enhancement
	case packageinfo.UpdateTypeOther:
		return capabilities.Other
	case packageinfo.UpdateTypeUnknown:
		return packageinfo.CapabilityUnknown
	default:
		return packageinfo.CapabilityUnknown
	}
}

func newPackageCapabilities(capabilities packageinfo.Capabilities) PackageCapabilities {
	return PackageCapabilities{
		Classification: PackageClassificationCapabilities{
			Security:    capabilities.Classification.Security.String(),
			Bugfix:      capabilities.Classification.Bugfix.String(),
			Enhancement: capabilities.Classification.Enhancement.String(),
			Other:       capabilities.Classification.Other.String(),
		},
		RepositoryAttribution: capabilities.RepositoryAttribution.String(),
		RebootDetection:       capabilities.RebootDetection.String(),
		LastUpdate:            capabilities.LastUpdate.String(),
		MetadataAge:           capabilities.MetadataAge.String(),
	}
}

func countPackageUpdateTypes(updates []packageinfo.Update) UpdateTypeCounts {
	var counts UpdateTypeCounts
	for _, update := range updates {
		switch update.Type {
		case packageinfo.UpdateTypeSecurity:
			counts.Security++
		case packageinfo.UpdateTypeBugfix:
			counts.Bugfix++
		case packageinfo.UpdateTypeEnhancement:
			counts.Enhancement++
		case packageinfo.UpdateTypeOther:
			counts.Other++
		case packageinfo.UpdateTypeUnknown:
			// Validation rejects this before aggregation.
		}
	}

	return counts
}
