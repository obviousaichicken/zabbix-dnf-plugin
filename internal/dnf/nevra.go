package dnf

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

var errInvalidNEVRA = errors.New("invalid NEVRA")

// NEVRA is an RPM package name, epoch, version, release, and architecture.
type NEVRA struct {
	Name    string
	Epoch   string
	Version string
	Release string
	Arch    string
}

// ParseNEVRA parses name-[epoch:]version-release.arch from right to left so
// hyphenated package names remain unambiguous.
func ParseNEVRA(value string) (NEVRA, error) {
	if value == "" || strings.TrimSpace(value) != value || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return NEVRA{}, fmt.Errorf("%w %q", errInvalidNEVRA, value)
	}

	archSeparator := strings.LastIndexByte(value, '.')
	if archSeparator <= 0 || archSeparator == len(value)-1 {
		return NEVRA{}, fmt.Errorf("%w %q: architecture is missing", errInvalidNEVRA, value)
	}

	prefix := value[:archSeparator]
	releaseSeparator := strings.LastIndexByte(prefix, '-')
	if releaseSeparator <= 0 || releaseSeparator == len(prefix)-1 {
		return NEVRA{}, fmt.Errorf("%w %q: release is missing", errInvalidNEVRA, value)
	}

	nameVersion := prefix[:releaseSeparator]
	nameSeparator := strings.LastIndexByte(nameVersion, '-')
	if nameSeparator <= 0 || nameSeparator == len(nameVersion)-1 {
		return NEVRA{}, fmt.Errorf("%w %q: name or version is missing", errInvalidNEVRA, value)
	}

	parsed := NEVRA{
		Name:    nameVersion[:nameSeparator],
		Version: nameVersion[nameSeparator+1:],
		Release: prefix[releaseSeparator+1:],
		Arch:    value[archSeparator+1:],
	}

	if epochSeparator := strings.IndexByte(parsed.Version, ':'); epochSeparator >= 0 {
		if epochSeparator == 0 || epochSeparator == len(parsed.Version)-1 ||
			strings.IndexByte(parsed.Version[epochSeparator+1:], ':') >= 0 {
			return NEVRA{}, fmt.Errorf("%w %q: epoch is malformed", errInvalidNEVRA, value)
		}
		parsed.Epoch = parsed.Version[:epochSeparator]
		parsed.Version = parsed.Version[epochSeparator+1:]
		if _, err := strconv.ParseUint(parsed.Epoch, 10, 64); err != nil {
			return NEVRA{}, fmt.Errorf("%w %q: epoch is not numeric", errInvalidNEVRA, value)
		}
	}

	if err := parsed.Validate(); err != nil {
		return NEVRA{}, fmt.Errorf("%w %q: %v", errInvalidNEVRA, value, err)
	}

	return parsed, nil
}

// NEVRAFromUpdate converts neutral DNF update fields without changing them.
func NEVRAFromUpdate(update packageinfo.Update) NEVRA {
	return NEVRA{
		Name:    update.Name,
		Epoch:   update.Epoch,
		Version: update.Version,
		Release: update.Release,
		Arch:    update.Arch,
	}
}

// Validate checks the structural fields used in an RPM identifier.
func (n NEVRA) Validate() error {
	fields := []struct {
		name  string
		value string
	}{
		{name: "name", value: n.Name},
		{name: "version", value: n.Version},
		{name: "release", value: n.Release},
		{name: "architecture", value: n.Arch},
	}
	for _, field := range fields {
		if field.value == "" {
			return fmt.Errorf("%s is empty", field.name)
		}
		if strings.IndexByte(field.value, 0) >= 0 || strings.IndexFunc(field.value, unicode.IsSpace) >= 0 {
			return fmt.Errorf("%s contains whitespace or NUL", field.name)
		}
	}
	if strings.ContainsAny(n.Name, ":/") {
		return errors.New("name contains a reserved separator")
	}
	if strings.ContainsAny(n.Version, ":-") {
		return errors.New("version contains a reserved separator")
	}
	if strings.ContainsAny(n.Release, ":-") {
		return errors.New("release contains a reserved separator")
	}
	if strings.ContainsAny(n.Arch, ".:-/") {
		return errors.New("architecture contains a reserved separator")
	}
	if strings.IndexFunc(n.Arch, unicode.IsLetter) < 0 {
		return errors.New("architecture contains no letter")
	}
	if n.Epoch != "" && n.Epoch != "(none)" {
		if _, err := strconv.ParseUint(n.Epoch, 10, 64); err != nil {
			return errors.New("epoch is not numeric")
		}
	}

	return nil
}

// EVR formats the epoch, version, and release without losing an explicit epoch.
func (n NEVRA) EVR() string {
	version := n.Version
	if n.Release != "" {
		version += "-" + n.Release
	}
	if n.Epoch != "" {
		version = n.Epoch + ":" + version
	}

	return version
}

// String formats name-[epoch:]version-release.arch.
func (n NEVRA) String() string {
	return n.Name + "-" + n.EVR() + "." + n.Arch
}

// matchKey treats an omitted, zero, or RPM '(none)' epoch as the same package
// identity while keeping every other field exact.
func (n NEVRA) matchKey() string {
	epoch := n.Epoch
	if epoch == "" || epoch == "(none)" {
		epoch = "0"
	}

	return n.Name + "\x00" + epoch + "\x00" + n.Version + "\x00" +
		n.Release + "\x00" + n.Arch
}

func (n NEVRA) exactKey() string {
	return n.Name + "\x00" + n.Epoch + "\x00" + n.Version + "\x00" +
		n.Release + "\x00" + n.Arch
}

func setUpdateIdentity(update *packageinfo.Update) {
	nevra := NEVRAFromUpdate(*update)
	update.FullVersion = nevra.EVR()
	update.Identifier = nevra.String()
}
