package safetech

// Version is the library version reported in the User-Agent header of
// requests sent to the CA.
//
// Release builds set it at link time:
//
//	go build -ldflags "-X github.com/edanko/safetech-go.Version=v1.2.3"
var Version = "dev"

// defaultUserAgent returns the User-Agent header value used when
// [Config.UserAgent] is empty.
func defaultUserAgent() string {
	return "safetech/" + Version
}
