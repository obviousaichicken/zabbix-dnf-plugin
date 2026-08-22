//go:build !linux

package command

import "os/exec"

func configureCommandCancellation(cmd *exec.Cmd) {
	cmd.WaitDelay = commandWaitDelay
}
