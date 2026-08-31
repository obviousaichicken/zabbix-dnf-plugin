// Package results builds the structured payload returned by the plugin.
package results

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

var (
	errDuplicateRepository = errors.New("duplicate repository ID")
	errUnknownRepository   = errors.New("unknown repository reference")
)

// Payload is the plugin response.
type Payload struct {
	Collection     Collection     `json:"collection"`
	Classification Classification `json:"classification"`
	Summary        Summary        `json:"summary"`
	Repositories   []Repository   `json:"repositories"`
	Updates        []Update       `json:"updates"`
}

// Collection records collection status and duration.
type Collection struct {
	Complete   bool  `json:"complete"`
	DurationMS int64 `json:"duration_ms"` //nolint:tagliatelle // JSON schema uses snake_case.
}

// Classification records advisory category completeness.
type Classification struct {
	Complete         bool     `json:"complete"`
	FailedCategories []string `json:"failed_categories"` //nolint:tagliatelle // JSON schema uses snake_case.
}

// Summary contains collection counts.
type Summary struct {
	Repositories   int              `json:"repositories"`
	Updates        int              `json:"updates"`
	UpdatesPending bool             `json:"updates_pending"`
	RebootPending  bool             `json:"reboot_pending"`
	UpdateTypes    UpdateTypeCounts `json:"update_types"`
	LastUpdate     LastUpdate       `json:"last_update"`
}

// UpdateTypeCounts contains advisory category counts.
type UpdateTypeCounts struct {
	Security    int `json:"security"`
	Bugfix      int `json:"bugfix"`
	Enhancement int `json:"enhancement"`
	Other       int `json:"other"`
}

// LastUpdate describes the most recent completed transaction that upgraded a package.
type LastUpdate struct {
	Timestamp *time.Time `json:"timestamp"`
	Result    string     `json:"result"`
}

// NewLastUpdate converts a neutral last update to payload form.
func NewLastUpdate(update *packageinfo.LastUpdate) LastUpdate {
	if update == nil {
		return LastUpdate{Result: packageinfo.LastUpdateResultNotRecorded}
	}

	return LastUpdate{
		Timestamp: &update.Timestamp,
		Result:    update.Result,
	}
}

// Repository contains a repository and its update count.
type Repository struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	UpdateCount int    `json:"update_count"` //nolint:tagliatelle // JSON schema uses snake_case.
}

// Update contains package update details.
type Update struct {
	RepositoryID string `json:"repository_id"` //nolint:tagliatelle // JSON schema uses snake_case.
	Name         string `json:"name"`
	Epoch        string `json:"epoch"`
	Version      string `json:"version"`
	Release      string `json:"release"`
	Arch         string `json:"arch"`
}

// Build creates a sorted plugin payload and validates repository references.
func Build(
	repositories []packageinfo.Repository,
	updates []packageinfo.Update,
) (Payload, error) {
	return BuildLegacy(repositories, updates)
}

// BuildLegacy creates the byte-compatible dnf.get payload.
//
//nolint:funlen // BuildLegacy keeps payload validation and ordering together.
func BuildLegacy(
	repositories []packageinfo.Repository,
	updates []packageinfo.Update,
) (Payload, error) {
	result := Payload{
		Collection: Collection{
			Complete: true,
		},
		Classification: Classification{
			Complete:         true,
			FailedCategories: make([]string, 0),
		},
		Summary: Summary{
			Repositories:   len(repositories),
			Updates:        len(updates),
			UpdatesPending: len(updates) > 0,
			RebootPending:  false,
			UpdateTypes:    countUpdateTypes(updates),
			LastUpdate:     NewLastUpdate(nil),
		},
		Repositories: make([]Repository, 0, len(repositories)),
		Updates:      make([]Update, 0, len(updates)),
	}

	repositoryIDs := make(map[string]struct{}, len(repositories))
	updateCounts := make(map[string]int, len(repositories))

	for _, repository := range repositories {
		if _, exists := repositoryIDs[repository.ID]; exists {
			return Payload{}, fmt.Errorf(
				"duplicate repository ID %q: %w",
				repository.ID,
				errDuplicateRepository,
			)
		}

		repositoryIDs[repository.ID] = struct{}{}

		result.Repositories = append(
			result.Repositories,
			Repository{
				ID:          repository.ID,
				Name:        repository.Name,
				UpdateCount: 0,
			},
		)
	}

	for _, update := range updates {
		if _, exists := repositoryIDs[update.RepositoryID]; !exists {
			return Payload{}, fmt.Errorf(
				"update %q references unknown repository %q: %w",
				update.Name,
				update.RepositoryID,
				errUnknownRepository,
			)
		}

		updateCounts[update.RepositoryID]++

		result.Updates = append(
			result.Updates,
			Update{
				RepositoryID: update.RepositoryID,
				Name:         update.Name,
				Epoch:        update.Epoch,
				Version:      update.Version,
				Release:      update.Release,
				Arch:         update.Arch,
			},
		)
	}

	for i := range result.Repositories {
		result.Repositories[i].UpdateCount = updateCounts[result.Repositories[i].ID]
	}

	sort.Slice(result.Repositories, func(i, j int) bool {
		return result.Repositories[i].ID < result.Repositories[j].ID
	})

	sort.Slice(result.Updates, func(i, j int) bool {
		left := result.Updates[i]
		right := result.Updates[j]

		if left.RepositoryID != right.RepositoryID {
			return left.RepositoryID < right.RepositoryID
		}

		if left.Name != right.Name {
			return left.Name < right.Name
		}

		return left.Arch < right.Arch
	})

	return result, nil
}

func countUpdateTypes(updates []packageinfo.Update) UpdateTypeCounts {
	counts := UpdateTypeCounts{
		Other: len(updates),
	}

	for _, update := range updates {
		switch update.Type {
		case packageinfo.UpdateTypeSecurity:
			counts.Security++
			counts.Other--
		case packageinfo.UpdateTypeBugfix:
			counts.Bugfix++
			counts.Other--
		case packageinfo.UpdateTypeEnhancement:
			counts.Enhancement++
			counts.Other--
		case packageinfo.UpdateTypeOther, packageinfo.UpdateTypeUnknown:
			continue
		}
	}

	return counts
}
