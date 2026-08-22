package dnf

import (
	"errors"
	"testing"
)

func TestCommandError(t *testing.T) {
	t.Parallel()

	cause := errors.New("command failed")
	tests := []struct {
		name       string
		exitStatus int
		want       string
	}{
		{
			name:       "with exit status",
			exitStatus: 1,
			want:       "dnf command failed with exit status 1: command failed",
		},
		{
			name:       "without exit status",
			exitStatus: -1,
			want:       "dnf command failed: command failed",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			err := &CommandError{
				ExitStatus: test.exitStatus,
				Err:        cause,
			}
			if got := err.Error(); got != test.want {
				t.Fatalf("CommandError.Error() = %q, want %q", got, test.want)
			}
			if !errors.Is(err, cause) {
				t.Fatal("CommandError does not unwrap its cause")
			}
		})
	}
}
