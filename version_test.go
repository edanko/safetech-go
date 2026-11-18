package safetech

import (
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionFromBuildInfo(t *testing.T) {
	t.Parallel()

	dependency := func(path, version string, replace *debug.Module) *debug.Module {
		return &debug.Module{Path: path, Version: version, Replace: replace}
	}

	tests := map[string]struct {
		info *debug.BuildInfo
		want string
	}{
		"no build information": {
			info: nil,
			want: "",
		},
		"built as this module": {
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "v1.2.3"}},
			want: "v1.2.3",
		},
		"test binary of this module": {
			info: &debug.BuildInfo{Main: debug.Module{Path: modulePath, Version: "(devel)"}},
			want: "",
		},
		"built as another program importing this module": {
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/service", Version: "(devel)"},
				Deps: []*debug.Module{dependency(modulePath, "v0.4.0", nil)},
			},
			want: "v0.4.0",
		},
		"replaced by a released version": {
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/service"},
				Deps: []*debug.Module{
					dependency(modulePath, "v0.4.0", &debug.Module{Path: modulePath, Version: "v0.5.1"}),
				},
			},
			want: "v0.5.1",
		},
		"replaced by a local directory": {
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/service"},
				Deps: []*debug.Module{
					dependency(modulePath, "v0.4.0", &debug.Module{Path: "../safetech-go", Version: "(devel)"}),
				},
			},
			want: "",
		},
		"dependency present without a version": {
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/service"},
				Deps: []*debug.Module{dependency(modulePath, "", nil)},
			},
			want: "",
		},
		"not a dependency": {
			info: &debug.BuildInfo{
				Main: debug.Module{Path: "example.com/service"},
				Deps: []*debug.Module{dependency("example.com/other", "v1.0.0", nil)},
			},
			want: "",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := versionFromBuildInfo(test.info); got != test.want {
				t.Errorf("versionFromBuildInfo() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestLibraryVersionFallsBack(t *testing.T) {
	t.Parallel()

	// A test binary of this module records "(devel)", so the only version
	// available is the fallback.
	version := libraryVersion()
	if version == "" {
		t.Fatal("libraryVersion() is empty")
	}

	if !strings.HasPrefix(defaultUserAgent(), "safetech/") {
		t.Errorf("user agent = %q, want the safetech/ prefix", defaultUserAgent())
	}
}

// TestVersionOverride is serial: it mutates the package-level Version used by
// every other test in the package.
func TestVersionOverride(t *testing.T) {
	previous := Version

	t.Cleanup(func() { Version = previous })

	Version = "v9.9.9"
	if got, want := defaultUserAgent(), "safetech/v9.9.9"; got != want {
		t.Errorf("user agent = %q, want %q", got, want)
	}

	// Stray whitespace from a linker value should not leak into the header.
	Version = "  v9.9.9  "
	if got, want := defaultUserAgent(), "safetech/v9.9.9"; got != want {
		t.Errorf("user agent = %q, want %q", got, want)
	}

	Version = ""
	if got := defaultUserAgent(); got == "safetech/" {
		t.Error("empty override must fall back to the detected version")
	}
}
