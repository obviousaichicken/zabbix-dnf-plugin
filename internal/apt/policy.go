package apt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

const (
	maxPolicyOutputBytes = 8 << 20
	maxPolicyLineBytes   = 1 << 20
)

// PolicySource is one configured source for the exact candidate version. Its
// position retains APT's tie-breaking order.
type PolicySource struct {
	RepositoryID string
	Source       string
	Priority     int
	Security     bool
}

// PackagePolicy contains APT's selected versions and all configured sources
// that provide the exact candidate version.
type PackagePolicy struct {
	Name                      string
	Architecture              string
	Installed                 *DebianVersion
	Candidate                 *DebianVersion
	CandidatePriority         int
	CandidatePhasedPercentage *int
	CandidateSources          []PolicySource
}

type rawPolicyBlock struct {
	identifier      string
	installedValue  string
	candidateValue  string
	hasInstalled    bool
	hasCandidate    bool
	hasVersionTable bool
	versions        []rawPolicyVersion
}

type rawPolicyVersion struct {
	version          DebianVersion
	priority         int
	phasedPercentage *int
	installedMarker  bool
	sources          []rawPolicySource
}

type rawPolicySource struct {
	priority    int
	description string
	status      bool
}

// ParsePackagePolicies parses one complete apt-cache policy batch and maps
// exact-candidate source lines to known, credential-free index targets.
func ParsePackagePolicies(
	data []byte,
	requested []InstalledPackage,
	indexes RepositoryIndexes,
) ([]PackagePolicy, error) {
	blocks, err := parsePolicyBlocks(data)
	if err != nil {
		return nil, fmt.Errorf("parse apt-cache policy: %w", err)
	}

	requestedByKey, requestedByName, err := requestedPolicyPackages(requested)
	if err != nil {
		return nil, err
	}
	if len(blocks) != len(requestedByKey) {
		return nil, fmt.Errorf(
			"apt-cache policy returned %d package blocks for %d requests",
			len(blocks),
			len(requestedByKey),
		)
	}
	targetsBySource, err := policyTargets(indexes)
	if err != nil {
		return nil, err
	}

	policies := make([]PackagePolicy, 0, len(blocks))
	seen := make(map[string]struct{}, len(blocks))
	for blockNumber, block := range blocks {
		pkg, resolveErr := resolvePolicyPackage(block.identifier, requestedByKey, requestedByName)
		if resolveErr != nil {
			return nil, fmt.Errorf("apt-cache policy block %d: %w", blockNumber+1, resolveErr)
		}
		key := packageKey(pkg.Name, pkg.Architecture)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate apt-cache policy block for %s:%s", pkg.Name, pkg.Architecture)
		}
		seen[key] = struct{}{}

		policy, buildErr := buildPackagePolicy(block, pkg, targetsBySource)
		if buildErr != nil {
			return nil, fmt.Errorf("apt-cache policy for %s:%s: %w", pkg.Name, pkg.Architecture, buildErr)
		}
		policies = append(policies, policy)
	}

	sort.Slice(policies, func(left, right int) bool {
		if policies[left].Name != policies[right].Name {
			return policies[left].Name < policies[right].Name
		}

		return policies[left].Architecture < policies[right].Architecture
	})

	return policies, nil
}

//nolint:cyclop // The state machine mirrors apt-cache policy's small indentation grammar.
func parsePolicyBlocks(data []byte) ([]rawPolicyBlock, error) {
	if len(data) > maxPolicyOutputBytes {
		return nil, fmt.Errorf("policy output exceeds %d bytes", maxPolicyOutputBytes)
	}

	blocks := make([]rawPolicyBlock, 0)
	blockIndex := -1
	versionIndex := -1
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), maxPolicyLineBytes)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := strings.TrimSuffix(scanner.Text(), "\r")
		if strings.IndexByte(line, 0) >= 0 {
			return nil, fmt.Errorf("malformed policy line %d: NUL byte", lineNumber)
		}
		if line == "" {
			continue
		}
		if strings.IndexByte(line, '\t') >= 0 {
			return nil, fmt.Errorf("malformed policy line %d: tabs are not permitted", lineNumber)
		}
		if line[0] != ' ' {
			identifier, headerErr := parsePolicyHeader(line)
			if headerErr != nil {
				return nil, fmt.Errorf("malformed policy line %d: %w", lineNumber, headerErr)
			}
			blocks = append(blocks, rawPolicyBlock{identifier: identifier})
			blockIndex = len(blocks) - 1
			versionIndex = -1
			continue
		}
		if blockIndex < 0 {
			return nil, fmt.Errorf("malformed policy line %d: content before package header", lineNumber)
		}

		block := &blocks[blockIndex]
		switch {
		case strings.HasPrefix(line, "  Installed: "):
			if block.hasInstalled || block.hasVersionTable {
				return nil, fmt.Errorf("malformed policy line %d: misplaced or duplicate Installed", lineNumber)
			}
			block.installedValue = strings.TrimSpace(strings.TrimPrefix(line, "  Installed: "))
			block.hasInstalled = block.installedValue != ""
			if !block.hasInstalled {
				return nil, fmt.Errorf("malformed policy line %d: empty Installed value", lineNumber)
			}
			continue
		case strings.HasPrefix(line, "  Candidate: "):
			if block.hasCandidate || block.hasVersionTable {
				return nil, fmt.Errorf("malformed policy line %d: misplaced or duplicate Candidate", lineNumber)
			}
			block.candidateValue = strings.TrimSpace(strings.TrimPrefix(line, "  Candidate: "))
			block.hasCandidate = block.candidateValue != ""
			if !block.hasCandidate {
				return nil, fmt.Errorf("malformed policy line %d: empty Candidate value", lineNumber)
			}
			continue
		case line == "  Version table:":
			if block.hasVersionTable || !block.hasInstalled || !block.hasCandidate {
				return nil, fmt.Errorf("malformed policy line %d: misplaced or duplicate Version table", lineNumber)
			}
			block.hasVersionTable = true
			versionIndex = -1
			continue
		}

		if !block.hasVersionTable {
			return nil, fmt.Errorf("malformed policy line %d: unexpected package property", lineNumber)
		}
		indentation := leadingSpaces(line)
		if indentation >= 8 {
			if versionIndex < 0 {
				return nil, fmt.Errorf("malformed policy line %d: source precedes version", lineNumber)
			}
			source, sourceErr := parsePolicySourceLine(strings.TrimSpace(line))
			if sourceErr != nil {
				return nil, fmt.Errorf("malformed policy line %d: %w", lineNumber, sourceErr)
			}
			block.versions[versionIndex].sources = append(block.versions[versionIndex].sources, source)
			continue
		}
		if indentation < 1 {
			return nil, fmt.Errorf("malformed policy line %d: invalid indentation", lineNumber)
		}
		version, versionErr := parsePolicyVersionLine(strings.TrimSpace(line))
		if versionErr != nil {
			return nil, fmt.Errorf("malformed policy line %d: %w", lineNumber, versionErr)
		}
		block.versions = append(block.versions, version)
		versionIndex = len(block.versions) - 1
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.New("malformed policy output: line exceeds parser limit")
	}

	for blockNumber, block := range blocks {
		if !block.hasInstalled || !block.hasCandidate || !block.hasVersionTable {
			return nil, fmt.Errorf("policy block %d is structurally incomplete", blockNumber+1)
		}
	}

	return blocks, nil
}

func parsePolicyHeader(line string) (string, error) {
	if !strings.HasSuffix(line, ":") {
		return "", errors.New("package header is missing trailing colon")
	}
	identifier := strings.TrimSuffix(line, ":")
	if identifier == "" || strings.TrimSpace(identifier) != identifier || strings.ContainsAny(identifier, "\r\n\t ") {
		return "", errors.New("invalid package header")
	}

	return identifier, nil
}

func parsePolicyVersionLine(line string) (rawPolicyVersion, error) {
	result := rawPolicyVersion{}
	if strings.HasPrefix(line, "*** ") {
		result.installedMarker = true
		line = strings.TrimPrefix(line, "*** ")
	}
	fields := strings.Fields(line)
	if len(fields) != 2 && len(fields) != 4 {
		return rawPolicyVersion{}, errors.New("invalid version-table row")
	}

	version, err := ParseDebianVersion(fields[0])
	if err != nil {
		return rawPolicyVersion{}, errors.New("invalid version-table version")
	}
	priority, err := parsePolicyPriority(fields[1])
	if err != nil {
		return rawPolicyVersion{}, err
	}
	result.version = version
	result.priority = priority

	if len(fields) == 4 {
		if fields[2] != "(phased" || !strings.HasSuffix(fields[3], "%)") {
			return rawPolicyVersion{}, errors.New("invalid phased-update annotation")
		}
		percentageText := strings.TrimSuffix(fields[3], "%)")
		percentage, percentageErr := strconv.Atoi(percentageText)
		if percentageErr != nil || percentage < 0 || percentage > 100 {
			return rawPolicyVersion{}, errors.New("invalid phased-update percentage")
		}
		result.phasedPercentage = &percentage
	}

	return result, nil
}

func parsePolicySourceLine(line string) (rawPolicySource, error) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return rawPolicySource{}, errors.New("invalid version source row")
	}
	priority, err := parsePolicyPriority(fields[0])
	if err != nil {
		return rawPolicySource{}, err
	}
	description := strings.Join(fields[1:], " ")
	if description == "/var/lib/dpkg/status" {
		return rawPolicySource{priority: priority, status: true}, nil
	}
	normalized, _, err := sanitizedDescription(description)
	if err != nil {
		return rawPolicySource{}, errors.New("invalid repository source row")
	}

	return rawPolicySource{priority: priority, description: normalized}, nil
}

func parsePolicyPriority(value string) (int, error) {
	priority, err := strconv.ParseInt(value, 10, 32)
	if err != nil {
		return 0, errors.New("invalid policy priority")
	}

	return int(priority), nil
}

func leadingSpaces(value string) int {
	for index, character := range []byte(value) {
		if character != ' ' {
			return index
		}
	}

	return len(value)
}

func requestedPolicyPackages(
	requested []InstalledPackage,
) (map[string]InstalledPackage, map[string][]InstalledPackage, error) {
	byKey := make(map[string]InstalledPackage, len(requested))
	byName := make(map[string][]InstalledPackage, len(requested))
	for _, pkg := range requested {
		if !validPackageName(pkg.Name) || !validArchitecture(pkg.Architecture) {
			return nil, nil, errors.New("invalid requested apt-cache policy package")
		}
		key := packageKey(pkg.Name, pkg.Architecture)
		if _, duplicate := byKey[key]; duplicate {
			return nil, nil, fmt.Errorf("duplicate requested apt-cache policy package %s:%s", pkg.Name, pkg.Architecture)
		}
		byKey[key] = pkg
		byName[pkg.Name] = append(byName[pkg.Name], pkg)
	}

	return byKey, byName, nil
}

func resolvePolicyPackage(
	identifier string,
	byKey map[string]InstalledPackage,
	byName map[string][]InstalledPackage,
) (InstalledPackage, error) {
	if separator := strings.LastIndexByte(identifier, ':'); separator >= 0 {
		name := identifier[:separator]
		architecture := identifier[separator+1:]
		if !validPackageName(name) || !validArchitecture(architecture) {
			return InstalledPackage{}, errors.New("invalid qualified package header")
		}
		pkg, exists := byKey[packageKey(name, architecture)]
		if !exists {
			return InstalledPackage{}, errors.New("unrequested package header")
		}

		return pkg, nil
	}
	if !validPackageName(identifier) {
		return InstalledPackage{}, errors.New("invalid package header")
	}
	candidates := byName[identifier]
	if len(candidates) != 1 {
		return InstalledPackage{}, errors.New("unqualified package header is missing or ambiguous")
	}

	return candidates[0], nil
}

func policyTargets(indexes RepositoryIndexes) (map[string]IndexTarget, error) {
	repositories := make(map[string]struct{}, len(indexes.Repositories))
	for _, repository := range indexes.Repositories {
		if repository.ID == "" {
			return nil, errors.New("APT repository index contains an empty repository ID")
		}
		if _, duplicate := repositories[repository.ID]; duplicate {
			return nil, fmt.Errorf("APT repository index contains duplicate repository ID %q", repository.ID)
		}
		repositories[repository.ID] = struct{}{}
	}

	targets := make(map[string]IndexTarget, len(indexes.Targets))
	for _, target := range indexes.Targets {
		if _, exists := repositories[target.RepositoryID]; !exists {
			return nil, errors.New("APT index target references an unknown repository")
		}
		if owner, duplicate := targets[target.Source]; duplicate &&
			(owner.RepositoryID != target.RepositoryID || owner.Security != target.Security) {
			return nil, errors.New("APT policy source has ambiguous index targets")
		}
		targets[target.Source] = target
	}

	return targets, nil
}

func buildPackagePolicy(
	block rawPolicyBlock,
	pkg InstalledPackage,
	targetsBySource map[string]IndexTarget,
) (PackagePolicy, error) {
	installed, err := optionalPolicyVersion(block.installedValue)
	if err != nil {
		return PackagePolicy{}, errors.New("invalid Installed version")
	}
	candidate, err := optionalPolicyVersion(block.candidateValue)
	if err != nil {
		return PackagePolicy{}, errors.New("invalid Candidate version")
	}

	markedVersion := ""
	versionsByFull := make(map[string]rawPolicyVersion, len(block.versions))
	for _, version := range block.versions {
		if _, duplicate := versionsByFull[version.version.Full]; duplicate {
			return PackagePolicy{}, errors.New("duplicate version-table version")
		}
		versionsByFull[version.version.Full] = version
		if version.installedMarker {
			if markedVersion != "" {
				return PackagePolicy{}, errors.New("multiple installed version markers")
			}
			markedVersion = version.version.Full
		}
	}
	if installed == nil && markedVersion != "" || installed != nil && markedVersion != installed.Full {
		return PackagePolicy{}, errors.New("installed version marker mismatch")
	}

	policy := PackagePolicy{
		Name:             pkg.Name,
		Architecture:     pkg.Architecture,
		Installed:        installed,
		Candidate:        candidate,
		CandidateSources: make([]PolicySource, 0),
	}
	if candidate == nil {
		return policy, nil
	}
	candidateVersion, exists := versionsByFull[candidate.Full]
	if !exists {
		return PackagePolicy{}, errors.New("Candidate has no exact version-table entry")
	}
	policy.CandidatePriority = candidateVersion.priority
	if candidateVersion.phasedPercentage != nil {
		percentage := *candidateVersion.phasedPercentage
		policy.CandidatePhasedPercentage = &percentage
	}
	for _, source := range candidateVersion.sources {
		if source.status {
			continue
		}
		target, mapped := targetsBySource[source.description]
		if !mapped {
			return PackagePolicy{}, errors.New("exact Candidate source has no matching APT index target")
		}
		policy.CandidateSources = append(policy.CandidateSources, PolicySource{
			RepositoryID: target.RepositoryID,
			Source:       target.Source,
			Priority:     source.priority,
			Security:     target.Security,
		})
	}
	if len(policy.CandidateSources) == 0 && (installed == nil || candidate.Full != installed.Full) {
		return PackagePolicy{}, errors.New("exact Candidate version has no repository source")
	}

	return policy, nil
}

func optionalPolicyVersion(value string) (*DebianVersion, error) {
	if value == "(none)" {
		return nil, nil
	}
	version, err := ParseDebianVersion(value)
	if err != nil {
		return nil, err
	}

	return &version, nil
}
