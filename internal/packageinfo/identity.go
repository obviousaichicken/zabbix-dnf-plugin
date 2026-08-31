package packageinfo

// FullVersion formats the lossless package version represented by an update.
func FullVersion(update Update) string {
	version := update.Version
	if update.Release != "" {
		version += "-" + update.Release
	}
	if update.Epoch != "" {
		version = update.Epoch + ":" + version
	}

	return version
}

// Identifier formats the stable display identifier for a backend update.
func Identifier(backend Backend, update Update) string {
	fullVersion := update.FullVersion
	if fullVersion == "" {
		fullVersion = FullVersion(update)
	}

	switch backend {
	case BackendDNF:
		return update.Name + "-" + fullVersion + "." + update.Arch
	case BackendAPT:
		return update.Name + ":" + update.Arch + "=" + fullVersion
	case BackendUnknown:
		return ""
	default:
		return ""
	}
}

// SetIdentity fills the derived full-version and identifier fields.
func SetIdentity(backend Backend, update *Update) {
	update.FullVersion = FullVersion(*update)
	update.Identifier = Identifier(backend, *update)
}
