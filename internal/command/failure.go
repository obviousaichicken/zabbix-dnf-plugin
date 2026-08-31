package command

// Failure is implemented by safe, structured external-command errors.
// Implementations must not expose credentials, unbounded arguments, or stderr
// through Operation.
type Failure interface {
	error
	Operation() string
	Status() int
	IsTimeout() bool
	IsCanceled() bool
}
