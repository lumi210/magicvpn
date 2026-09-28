package license

import (
	"crypto/ed25519"
	"os"
	"strings"
)

// DefaultServerURL is the production license server base URL. Production
// deployments replace both this URL and DefaultKeys with production values.
const DefaultServerURL = "https://license.magicvpn.example"

// ServerURLFromEnv returns the configured license server URL, allowing an
// explicit override for testing and operations.
func ServerURLFromEnv() string {
	if value := strings.TrimSpace(os.Getenv("MAGICVPN_LICENSE_URL")); value != "" {
		return value
	}
	return DefaultServerURL
}

// DefaultKeys contains the public keys trusted for license signatures.
var DefaultKeys = map[string]ed25519.PublicKey{
	"mk-1": {
		0x03, 0x77, 0x87, 0x09, 0x05, 0xd1, 0x7d, 0x5c,
		0x36, 0xfd, 0x1b, 0x65, 0x98, 0x71, 0x2f, 0x74,
		0x9e, 0xd2, 0x35, 0x2d, 0x3b, 0x77, 0x93, 0xdc,
		0xed, 0x04, 0x4b, 0x07, 0x7e, 0x51, 0x48, 0xa3,
	},
}
