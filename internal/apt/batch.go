package apt

import (
	"errors"
	"fmt"
)

const (
	maxPolicyPackageArguments = 512
	maxPolicyArgumentBytes    = 64 << 10
)

// BatchPolicyArguments creates bounded apt-cache policy argument batches. The
// byte count includes each argument's terminating NUL in the exec argv.
func BatchPolicyArguments(packages []InstalledPackage) ([][]string, error) {
	if len(packages) == 0 {
		return make([][]string, 0), nil
	}

	batches := make([][]string, 0, (len(packages)+maxPolicyPackageArguments-1)/maxPolicyPackageArguments)
	batch := make([]string, 0, min(len(packages), maxPolicyPackageArguments))
	batchBytes := 0
	seen := make(map[string]struct{}, len(packages))

	for _, pkg := range packages {
		if !validPackageName(pkg.Name) || !validArchitecture(pkg.Architecture) {
			return nil, errors.New("invalid package identity for apt-cache policy")
		}
		key := packageKey(pkg.Name, pkg.Architecture)
		if _, duplicate := seen[key]; duplicate {
			return nil, fmt.Errorf("duplicate apt-cache policy package %s:%s", pkg.Name, pkg.Architecture)
		}
		seen[key] = struct{}{}

		argument := pkg.Name + ":" + pkg.Architecture
		argumentBytes := len(argument) + 1
		if argumentBytes > maxPolicyArgumentBytes {
			return nil, errors.New("apt-cache policy argument exceeds byte limit")
		}
		if len(batch) == maxPolicyPackageArguments || batchBytes+argumentBytes > maxPolicyArgumentBytes {
			batches = append(batches, batch)
			batch = make([]string, 0, min(len(packages)-len(seen)+1, maxPolicyPackageArguments))
			batchBytes = 0
		}
		batch = append(batch, argument)
		batchBytes += argumentBytes
	}
	if len(batch) != 0 {
		batches = append(batches, batch)
	}

	return batches, nil
}
