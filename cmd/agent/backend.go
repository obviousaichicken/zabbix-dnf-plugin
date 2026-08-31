package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/obviousaichicken/zabbix-dnf-plugin/internal/packageinfo"
)

const (
	backendAuto = "auto"
	backendDNF  = "dnf"
	backendAPT  = "apt"
)

var (
	errInvalidBackendOption = errors.New("Backend must be one of auto, dnf, or apt")
	errAmbiguousBackend     = errors.New("ambiguous package-manager family")
	errUnsupportedBackend   = errors.New("unsupported operating-system package manager")
)

type backendSelection struct {
	Backend packageinfo.Backend
	Paths   map[string]string
}

func parseBackendOption(privateOptions any) (string, error) {
	if privateOptions == nil {
		return backendAuto, nil
	}

	var value any
	switch options := privateOptions.(type) {
	case map[string]any:
		if _, tree := options["Name"]; tree {
			backend, err := parsePrivateOptionTree(options)
			if err != nil {
				return "", err
			}
			value = backend

			break
		}
		if len(options) == 0 {
			return backendAuto, nil
		}
		var exists bool
		value, exists = options["Backend"]
		if !exists || len(options) != 1 {
			return "", fmt.Errorf(
				"invalid private plugin option keys %v: %w",
				sortedOptionKeys(options),
				errInvalidBackendOption,
			)
		}
	case map[string]string:
		if len(options) == 0 {
			return backendAuto, nil
		}
		var exists bool
		value, exists = options["Backend"]
		if !exists || len(options) != 1 {
			return "", fmt.Errorf(
				"invalid private plugin option keys %v: %w",
				sortedOptionKeys(options),
				errInvalidBackendOption,
			)
		}
	default:
		return "", fmt.Errorf("private plugin options have type %T: %w", privateOptions, errInvalidBackendOption)
	}

	backend, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("Backend has type %T: %w", value, errInvalidBackendOption)
	}
	if backend != backendAuto && backend != backendDNF && backend != backendAPT {
		return "", fmt.Errorf("Backend %q is invalid: %w", backend, errInvalidBackendOption)
	}

	return backend, nil
}

func parsePrivateOptionTree(root map[string]any) (string, error) {
	name, ok := root["Name"].(string)
	if !ok || name != pluginName {
		return "", errors.New("private plugin option tree has an invalid root")
	}
	rawNodes, exists := root["Nodes"]
	if !exists || rawNodes == nil {
		return backendAuto, nil
	}
	nodes, ok := rawNodes.([]any)
	if !ok {
		return "", errors.New("private plugin option tree Nodes is not an array")
	}
	if len(nodes) == 0 {
		return backendAuto, nil
	}

	var option map[string]any
	for _, rawNode := range nodes {
		node, ok := rawNode.(map[string]any)
		if !ok {
			return "", errors.New("private plugin option is not an object")
		}
		optionName, ok := node["Name"].(string)
		if !ok {
			return "", errors.New("private plugin option name is missing")
		}
		switch optionName {
		case "Backend":
			if option != nil {
				return "", errors.New("Backend private plugin option is duplicated")
			}
			option = node
		case "System":
			// Agent 2 7.0 includes its own external-plugin System subtree;
			// later families filter it before sending private options.
			continue
		default:
			return "", fmt.Errorf("private plugin option %q is unsupported", optionName)
		}
	}
	if option == nil {
		return backendAuto, nil
	}

	valueNodes, ok := option["Nodes"].([]any)
	if !ok || len(valueNodes) != 1 {
		return "", errors.New("Backend private plugin option must contain one value")
	}
	valueNode, ok := valueNodes[0].(map[string]any)
	if !ok {
		return "", errors.New("Backend private plugin option value is not an object")
	}
	encoded, ok := valueNode["Value"].(string)
	if !ok {
		return "", errors.New("Backend private plugin option value is missing")
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || !utf8.Valid(decoded) {
		return "", errors.New("Backend private plugin option value is not valid base64 UTF-8")
	}

	return string(decoded), nil
}

func sortedOptionKeys[T any](options map[string]T) []string {
	keys := make([]string, 0, len(options))
	for key := range options {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	return keys
}

func selectBackend(
	configured string,
	osReleaseData []byte,
	lookup func(string) (string, error),
) (backendSelection, error) {
	var backend packageinfo.Backend
	switch configured {
	case backendDNF:
		backend = packageinfo.BackendDNF
	case backendAPT:
		backend = packageinfo.BackendAPT
	case backendAuto:
		values, err := parseOSRelease(osReleaseData)
		if err != nil {
			return backendSelection{}, fmt.Errorf("parse /etc/os-release: %w", err)
		}

		backend, err = detectOSBackend(values["ID"], values["ID_LIKE"])
		if err != nil {
			return backendSelection{}, err
		}
	default:
		return backendSelection{}, errInvalidBackendOption
	}

	paths, err := lookupBackendCommands(backend, lookup)
	if err != nil {
		return backendSelection{}, err
	}

	return backendSelection{Backend: backend, Paths: paths}, nil
}

func detectOSBackend(id, idLike string) (packageinfo.Backend, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	switch id {
	case "debian", "ubuntu":
		return packageinfo.BackendAPT, nil
	case "fedora", "rhel", "centos", "rocky", "almalinux":
		return packageinfo.BackendDNF, nil
	}

	aptFamily := false
	dnfFamily := false
	for _, family := range strings.Fields(strings.ToLower(idLike)) {
		switch family {
		case "debian", "ubuntu":
			aptFamily = true
		case "fedora", "rhel", "centos":
			dnfFamily = true
		}
	}

	switch {
	case aptFamily && dnfFamily:
		return packageinfo.BackendUnknown, fmt.Errorf(
			"%w for ID=%q ID_LIKE=%q; set Plugins.DNF.Backend explicitly",
			errAmbiguousBackend,
			id,
			idLike,
		)
	case aptFamily:
		return packageinfo.BackendAPT, nil
	case dnfFamily:
		return packageinfo.BackendDNF, nil
	default:
		return packageinfo.BackendUnknown, fmt.Errorf(
			"%w for ID=%q ID_LIKE=%q; set Plugins.DNF.Backend explicitly",
			errUnsupportedBackend,
			id,
			idLike,
		)
	}
}

func lookupBackendCommands(
	backend packageinfo.Backend,
	lookup func(string) (string, error),
) (map[string]string, error) {
	var commands []string
	switch backend {
	case packageinfo.BackendDNF:
		commands = []string{"dnf", "rpm", "uname"}
	case packageinfo.BackendAPT:
		commands = []string{"apt-get", "apt-cache", "dpkg-query", "dpkg"}
	case packageinfo.BackendUnknown:
		return nil, errUnsupportedBackend
	}

	paths := make(map[string]string, len(commands))
	for _, command := range commands {
		path, err := lookup(command)
		if err != nil {
			return nil, fmt.Errorf(
				"%s backend requires executable %q: %w",
				backend.String(),
				command,
				err,
			)
		}
		paths[command] = path
	}

	return paths, nil
}

func parseOSRelease(data []byte) (map[string]string, error) {
	values := make(map[string]string)
	for lineNumber, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		key, rawValue, ok := strings.Cut(line, "=")
		if !ok || key == "" || strings.TrimSpace(key) != key {
			return nil, fmt.Errorf("line %d is not KEY=VALUE", lineNumber+1)
		}
		if _, exists := values[key]; exists {
			return nil, fmt.Errorf("line %d duplicates %s", lineNumber+1, key)
		}

		value, err := parseOSReleaseValue(rawValue)
		if err != nil {
			return nil, fmt.Errorf("line %d value for %s: %w", lineNumber+1, key, err)
		}
		values[key] = value
	}
	if values["ID"] == "" {
		return nil, errors.New("ID is missing")
	}

	return values, nil
}

func parseOSReleaseValue(raw string) (string, error) {
	if raw == "" {
		return "", nil
	}
	if raw[0] != '\'' && raw[0] != '"' {
		if strings.ContainsAny(raw, " \t\r") {
			return "", errors.New("unquoted value contains whitespace")
		}

		return raw, nil
	}

	quote := raw[0]
	if len(raw) < 2 || raw[len(raw)-1] != quote {
		return "", errors.New("unterminated quoted value")
	}
	value := raw[1 : len(raw)-1]
	if quote == '\'' {
		if strings.ContainsRune(value, '\'') {
			return "", errors.New("single-quoted value contains a quote")
		}

		return value, nil
	}

	var result strings.Builder
	result.Grow(len(value))
	for index := 0; index < len(value); index++ {
		if value[index] != '\\' {
			result.WriteByte(value[index])

			continue
		}
		index++
		if index >= len(value) {
			return "", errors.New("trailing escape")
		}
		switch value[index] {
		case '"', '\\', '$', '`':
			result.WriteByte(value[index])
		default:
			result.WriteByte('\\')
			result.WriteByte(value[index])
		}
	}

	return result.String(), nil
}
