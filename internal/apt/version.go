package apt

import (
	"errors"
	"strings"
)

// DebianVersion is a lossless Debian package version split into fields that
// map onto the package-manager-neutral version model.
type DebianVersion struct {
	Full    string
	Epoch   string
	Version string
	Release string
}

// ParseDebianVersion validates and splits [epoch:]upstream[-revision]. Ordering
// is deliberately left to dpkg --compare-versions.
func ParseDebianVersion(full string) (DebianVersion, error) {
	if full == "" || strings.ContainsAny(full, "\x00\r\n\t |=") {
		return DebianVersion{}, errors.New("invalid Debian version")
	}

	result := DebianVersion{Full: full}
	remainder := full
	if separator := strings.IndexByte(remainder, ':'); separator >= 0 {
		result.Epoch = remainder[:separator]
		if result.Epoch == "" || !allDigits(result.Epoch) {
			return DebianVersion{}, errors.New("invalid Debian version epoch")
		}
		remainder = remainder[separator+1:]
	}
	if remainder == "" || remainder[0] < '0' || remainder[0] > '9' {
		return DebianVersion{}, errors.New("invalid Debian upstream version")
	}

	result.Version = remainder
	if separator := strings.LastIndexByte(remainder, '-'); separator >= 0 {
		result.Version = remainder[:separator]
		result.Release = remainder[separator+1:]
		if result.Version == "" || result.Release == "" {
			return DebianVersion{}, errors.New("invalid Debian version revision")
		}
	}
	if !validVersionPart(result.Version, true) ||
		result.Release != "" && !validVersionPart(result.Release, false) {
		return DebianVersion{}, errors.New("invalid Debian version characters")
	}

	return result, nil
}

func allDigits(value string) bool {
	for _, character := range []byte(value) {
		if character < '0' || character > '9' {
			return false
		}
	}

	return value != ""
}

func validVersionPart(value string, upstream bool) bool {
	for _, character := range []byte(value) {
		if character >= '0' && character <= '9' ||
			character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			strings.ContainsRune(".+~", rune(character)) ||
			upstream && (character == '-' || character == ':') {
			continue
		}

		return false
	}

	return value != ""
}
