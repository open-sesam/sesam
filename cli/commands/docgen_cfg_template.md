# Config Reference

`sesam.yml` is the *declared* state of the repository: it describes who the
users are, how they are grouped, and which secrets exist. `sesam apply` diffs
this file against the verified audit log and proposes the changes needed to
bring both in sync.

## Key concepts

**The `admin` group is always implicit.** Every secret automatically includes
`admin` in its access list, regardless of what is written in `sesam.yml`. Listing
`admin` explicitly under a secret's `access:` is valid but redundant.

**An absent or empty `access` list means admin-only.** If you do not specify
`access:` on a secret, only members of the `admin` group can reveal it.

**Public key formats.** A user's `key` field accepts four forms:

- A literal SSH or age public key (e.g. `ssh-ed25519 AAAA…`)
- A forge identity shorthand (e.g. `github:alice`)
- An HTTPS URL pointing to a public key (treated the same as a forge-id)
- A local file path (useful for larger or machine-generated keys)

Forge-ids and URLs are resolved by the admin on first use. Any subsequent
change to the remote content is flagged as a warning when running `sesam
verify`.

## YAML anchors

If you want to re-use a part of your configuration, you can create a snippet:

```yaml
# Everything starting with "x-" on toplevel will be ignored.
x-default-access: &default-access
  access:
    - group1
    - group2
    - group3

# Use it: 
secrets:
  - path: foo.txt
    <<: *default-access
  - path: bar.txt
    <<: *default-access
```
  

For less often-used snippets it is sometimes useful to just reference another part directly:

```yaml
secrets:
  - path: foo.txt
    access: &default-access
      - group1
      - group2
      - group3
  - path: bar.txt
    <<: *default-access
```

Read up on [YAML anchors](https://en.wikipedia.org/wiki/YAML#Advanced_components) for more background.

---

<!-- Generated from config/sesam_schema.json via `task docgen:cfg`. Do not edit below this line. -->

{{ $root := . -}}
{{ range propOrder $root -}}
{{ $name := . -}}
{{ $prop := index $root.Properties $name -}}

## `{{ $name }}{{ if $prop.Items }}[]{{ end }}`

{{ $prop.Description }}

{{ if and $prop.Items $prop.Items.OneOf -}}
{{ range $prop.Items.OneOf -}}
{{ $variant := . }}
### {{ $variant.Description }}

| Field | Type | Required | Description |
|---|---|---|---|
{{ range propOrder $variant -}}{{ $f := . -}}{{ $fp := index $variant.Properties $f -}}
| `{{ $f }}` | `{{ typeStr $fp }}` | {{ if isRequired $variant $f }}yes{{ else }}no{{ end }} | {{ $fp.Description }} |
{{ end }}
{{ end -}}
{{ else if and $prop.Items $prop.Items.Properties -}}
| Field | Type | Required | Description |
|---|---|---|---|
{{ range propOrder $prop.Items -}}{{ $f := . -}}{{ $fp := index $prop.Items.Properties $f -}}
| `{{ $f }}` | `{{ typeStr $fp }}` | {{ if isRequired $prop.Items $f }}yes{{ else }}no{{ end }} | {{ $fp.Description }} |
{{ end }}
{{ else if $prop.AdditionalProperties -}}
Each value is `{{ typeStr $prop.AdditionalProperties }}`.

{{ else -}}
| | |
|---|---|
| **Type** | `{{ typeStr $prop }}` |
| **Required** | no |
{{- if $prop.Default }}
| **Default** | `{{ defaultStr $prop.Default }}` |
{{- end }}
{{- range constraints $prop }}
| **Constraint** | {{ . }} |
{{- end }}

{{ end -}}
---

{{ end -}}
## Complete example

```yaml
version: 1

users:
  - name: alice@example.com
    desc: Alice, team lead
    key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyMaterial
  - name: bob@example.com
    desc: Bob, developer
    key:
      - ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAnotherKeyMaterial
      - github:bob

groups:
  admin:
    - alice@example.com
  dev:
    - alice@example.com
    - bob@example.com

secrets:
  - path: README.md
  - path: secrets/api_key
    desc: Production API key for the payment service
    access:
      - dev
  - include: services/sesam.yml
```
