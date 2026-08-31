package dnf

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var (
	errInvalidAdvisoryID = errors.New("invalid advisory ID")
	cvePattern           = regexp.MustCompile(`\bCVE-[0-9]{4}-[0-9]{4,}\b`)
)

func validateAdvisoryID(id string) error {
	if id == "" || strings.TrimSpace(id) != id {
		return errInvalidAdvisoryID
	}
	for _, character := range id {
		if unicode.IsLetter(character) || unicode.IsDigit(character) ||
			strings.ContainsRune("-_.:+", character) {
			continue
		}

		return fmt.Errorf("%w %q", errInvalidAdvisoryID, id)
	}

	return nil
}

func extractCVEIDs(value string) []string {
	return cvePattern.FindAllString(value, -1)
}
