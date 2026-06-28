module github.com/open-sesam/sesam

go 1.26.4

require (
	filippo.io/age v1.3.1
	github.com/Masterminds/semver/v3 v3.5.0
	github.com/chzyer/readline v1.5.1
	github.com/go-git/go-git/v5 v5.19.1
	github.com/goccy/go-yaml v1.19.2
	github.com/gofrs/flock v0.12.1
	github.com/google/renameio/v2 v2.0.2
	github.com/google/uuid v1.6.0
	github.com/jedib0t/go-pretty/v6 v6.8.0
	github.com/mattn/go-colorable v0.1.14
	github.com/muesli/termenv v0.16.0
	github.com/multiformats/go-multihash v0.2.3
	github.com/neilotoole/jsoncolor v0.9.1
	github.com/rogpeppe/go-internal v1.14.1
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2
	github.com/stretchr/testify v1.11.1
	github.com/urfave/cli-docs/v3 v3.1.0
	github.com/urfave/cli/v3 v3.8.0
	github.com/zalando/go-keyring v0.2.7
	golang.org/x/crypto v0.52.0
	golang.org/x/sys v0.45.0
	golang.org/x/term v0.43.0
)

require (
	dario.cat/mergo v1.0.0 // indirect
	filippo.io/edwards25519 v1.1.1 // indirect
	filippo.io/hpke v0.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.1.6 // indirect
	github.com/aymanbagabas/go-osc52/v2 v2.0.1 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.2 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/danieljoos/wincred v1.2.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-git/go-billy/v5 v5.9.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.2.0 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/lucasb-eyer/go-colorful v1.2.0 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/minio/sha256-simd v1.0.0 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/multiformats/go-varint v0.0.6 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sergi/go-diff v1.3.2-0.20230802210424-5b0b94c5c0d3 // indirect
	github.com/skeema/knownhosts v1.3.1 // indirect
	github.com/spaolacci/murmur3 v1.1.0 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.44.0 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	lukechampine.com/blake3 v1.1.6 // indirect
)

// Used for this patch: https://github.com/google/renameio/issues/46
replace github.com/google/renameio/v2 => github.com/sahib/renameio/v2 v2.0.0-20260621194143-d21c25781e22
