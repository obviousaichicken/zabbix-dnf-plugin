package dnf

import (
	"context"
	"fmt"
)

const updateQueryFormat = `%{name}|%{epoch}|%{version}|%{release}|%{arch}|%{repoid}\n`

// Updates returns available package updates from enabled repositories.
func (c *Client) Updates(ctx context.Context) ([]Update, error) {
	updates, err := c.queryUpdates(ctx, "")
	if err != nil {
		return nil, fmt.Errorf("query updates: %w", err)
	}

	if len(updates) == 0 {
		return updates, nil
	}

	for _, updateType := range []struct {
		flag       string
		updateType UpdateType
	}{
		{flag: "--security", updateType: UpdateTypeSecurity},
		{flag: "--bugfix", updateType: UpdateTypeBugfix},
		{flag: "--enhancement", updateType: UpdateTypeEnhancement},
	} {
		classified, err := c.queryUpdates(ctx, updateType.flag)
		if err != nil {
			return nil, fmt.Errorf("query %s updates: %w", updateType.flag[2:], err)
		}

		markUpdateType(updates, classified, updateType.updateType)
	}

	return updates, nil
}

func (c *Client) queryUpdates(ctx context.Context, filter string) ([]Update, error) {
	args := []string{
		"-q",
		"--setopt=*.skip_if_unavailable=False",
		"repoquery",
		"--upgrades",
	}

	if filter != "" {
		args = append(args, filter)
	}

	args = append(
		args,
		"--latest-limit=1",
		"--queryformat",
		updateQueryFormat,
	)

	result, err := c.run(ctx, args...)
	if err != nil {
		return nil, err
	}

	return ParseUpdates(result.Stdout)
}

func markUpdateType(updates, classified []Update, updateType UpdateType) {
	classifiedPackages := make(map[string]struct{}, len(classified))
	for _, update := range classified {
		classifiedPackages[updatePackageKey(update)] = struct{}{}
	}

	for index := range updates {
		if updates[index].Type != UpdateTypeOther {
			continue
		}

		if _, exists := classifiedPackages[updatePackageKey(updates[index])]; exists {
			updates[index].Type = updateType
		}
	}
}

func updatePackageKey(update Update) string {
	return NEVRAFromUpdate(update).exactKey() + "\x00" + update.RepositoryID
}
