package dnf

import (
	"context"
	"strings"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/command"
)

func runCommand(
	ctx context.Context,
	runner Runner,
	path string,
	args []string,
	acceptedExitCodes []int,
) (command.Result, error) {
	result, err := runner.Run(ctx, command.Request{
		Name:              path,
		Args:              args,
		AcceptedExitCodes: acceptedExitCodes,
		Env: map[string]string{
			"LC_ALL": "C",
			"LANG":   "C",
		},
	})
	if err != nil {
		return result, &CommandError{
			Command:    path + " " + strings.Join(args, " "),
			ExitStatus: result.ExitCode,
			Stderr:     strings.TrimSpace(string(result.Stderr)),
			Err:        err,
		}
	}

	return result, nil
}
