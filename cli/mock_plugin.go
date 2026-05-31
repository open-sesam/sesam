package cli

import (
	"fmt"
	"os"

	"filippo.io/age"
	"filippo.io/age/plugin"
)

// RunMockPlugin is the entry point for the `age-plugin-sesamtest` test binary.
// It's wired into TestMain so testscript can drop a copy of the test
// executable into a temporary $PATH as `age-plugin-sesamtest`; sesam's plugin
// client then spawns it the same way it would spawn `age-plugin-yubikey`,
// exercising the full plugin protocol round-trip in CI without real hardware.
//
// The mock wraps a fixed X25519 keypair: HandleRecipient returns the public
// side, HandleIdentity returns the private side. The plugin's bech32 payload
// is ignored - the keypair is statically compiled in - so every "sesamtest"
// recipient/identity refers to the same key.
const mockPluginName = "sesamtest"

// Pre-generated X25519 keypair for tests; not security-sensitive.
const (
	mockIdentityString = "AGE-SECRET-KEY-1ACZL9JCUWCCWH2UANZP8EA6EPKLZEULJYEZTPUU5R2HCFJJNYVESXYLL5S"
)

// mockPayload is the bech32 payload of the plugin recipient/identity. The
// plugin ignores it - the real key material lives in mockIdentityString -
// but bech32 still needs *something* of plausible length to encode.
var mockPayload = []byte{0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb}

func RunMockPlugin() {
	p, err := plugin.New(mockPluginName)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	p.HandleRecipient(func(_ []byte) (age.Recipient, error) {
		return age.ParseX25519Recipient(mockX25519Recipient())
	})
	p.HandleIdentity(func(_ []byte) (age.Identity, error) {
		return age.ParseX25519Identity(mockIdentityString)
	})

	os.Exit(p.Main())
}

func mockX25519Recipient() string {
	id, err := age.ParseX25519Identity(mockIdentityString)
	if err != nil {
		panic(err)
	}
	return id.Recipient().String()
}

// MockPluginRecipient returns the bech32 recipient string the mock plugin
// answers to (`age1sesamtest1…`). Test setup uses it to write recipients
// users can be told about.
func MockPluginRecipient() string {
	return plugin.EncodeRecipient(mockPluginName, mockPayload)
}

// MockPluginIdentityFile returns the contents of an identity file pointing
// at the mock plugin, including the `# public key:` header sesam requires.
func MockPluginIdentityFile() string {
	return fmt.Sprintf(
		"# created: 2026-05-16\n# public key: %s\n%s\n",
		MockPluginRecipient(),
		plugin.EncodeIdentity(mockPluginName, mockPayload),
	)
}
