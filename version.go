package safetech

import (
	"cmp"
	"runtime/debug"
	"strings"
)

// modulePath is this module's own path. It is how the library finds its version
// in the build information of the program that imports it.
const modulePath = "github.com/edanko/safetech-go"

// fallbackVersion is reported when the build information carries no version,
// which is the case for test binaries and for builds that replace this module
// with a local directory.
const fallbackVersion = "dev"

// Version overrides the version reported in the User-Agent header.
//
// Normally it stays empty: the version is read from the build information of the
// program that imports this module, so consumers report the version they
// actually built against without changing their build at all. Set it only to
// force a specific value, either in code before the first [New] call or at link
// time:
//
//	go build -ldflags "-X github.com/edanko/safetech-go.Version=v1.2.3"
var Version string

// libraryVersion returns the version reported in the User-Agent header.
func libraryVersion() string {
	if version := strings.TrimSpace(Version); version != "" {
		return version
	}

	return cmp.Or(versionFromBuildInfo(buildInfo()), fallbackVersion)
}

// defaultUserAgent returns the User-Agent header value used when
// [Config.UserAgent] is empty.
func defaultUserAgent() string {
	return "safetech/" + libraryVersion()
}

// buildInfo returns the module build information of the running program, or nil
// when the binary carries none.
func buildInfo() *debug.BuildInfo {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return nil
	}

	return info
}

// versionFromBuildInfo extracts this module's version from the build information
// of a program: from the main module when the program is this module, otherwise
// from the dependency list.
func versionFromBuildInfo(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}

	if info.Main.Path == modulePath {
		if version := moduleVersion(info.Main); version != "" {
			return version
		}
	}

	for _, dependency := range info.Deps {
		if dependency.Path == modulePath {
			return moduleVersion(*dependency)
		}
	}

	return ""
}

// moduleVersion returns the version recorded for mod, following a replace
// directive, and empty when the build carries no release version.
func moduleVersion(mod debug.Module) string {
	if mod.Replace != nil {
		mod = *mod.Replace
	}

	// A local replace or a test binary records "(devel)" rather than a release.
	if mod.Version == "" || mod.Version == "(devel)" {
		return ""
	}

	return mod.Version
}
