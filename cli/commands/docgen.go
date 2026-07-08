package commands

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/template"

	clidocs "github.com/urfave/cli-docs/v3"
	"github.com/urfave/cli/v3"
	"opensesam.org/sesam/config"
)

//go:embed docgen_cfg_template.md
var cfgDocTemplate string

// HandleDocGenCLI writes a markdown CLI command reference to stdout.
func HandleDocGenCLI(_ context.Context, cmd *cli.Command) error {
	root := cmd.Root()
	stripHelpCommands(root)

	md, err := clidocs.ToMarkdown(root)
	if err != nil {
		return err
	}

	fmt.Println(md)
	return nil
}

// HandleDocGenConfig renders the config reference from sesam_schema.json to stdout.
func HandleDocGenConfig(_ context.Context, _ *cli.Command) error {
	raw, err := config.RawSchema()
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}

	var root cfgSchema
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("parse schema: %w", err)
	}

	resolved := cfgResolveAll(&root, root.Defs)

	funcMap := template.FuncMap{
		"typeStr":     cfgTypeStr,
		"defaultStr":  cfgDefaultStr,
		"isRequired":  cfgIsRequired,
		"constraints": cfgConstraints,
		"propOrder":   propOrder,
	}

	tmpl, err := template.New("config_ref").Funcs(funcMap).Parse(cfgDocTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	return tmpl.Execute(os.Stdout, resolved)
}

// stripHelpCommands recursively removes the auto-injected "help" subcommand.
func stripHelpCommands(cmd *cli.Command) {
	kept := cmd.Commands[:0]
	for _, sub := range cmd.Commands {
		if sub.Name == "help" {
			continue
		}
		stripHelpCommands(sub)
		kept = append(kept, sub)
	}
	cmd.Commands = kept
}

// cfgSchema represents a JSON Schema node. Only fields present in
// sesam_schema.json are decoded; unknown fields are silently ignored.
type cfgSchema struct {
	Title                string                `json:"title"`
	Description          string                `json:"description"`
	Type                 json.RawMessage       `json:"type"` // string or []string
	Properties           map[string]*cfgSchema `json:"properties"`
	AdditionalProperties *cfgSchema            `json:"additionalProperties"`
	Items                *cfgSchema            `json:"items"`
	OneOf                []*cfgSchema          `json:"oneOf"`
	AnyOf                []*cfgSchema          `json:"anyOf"`
	Ref                  string                `json:"$ref"`
	Defs                 map[string]*cfgSchema `json:"$defs"`
	Required             []string              `json:"required"`
	Default              json.RawMessage       `json:"default"`
	Minimum              *float64              `json:"minimum"`
	Maximum              *float64              `json:"maximum"`
	MinLength            *int                  `json:"minLength"`
	Order                *int                  `json:"x-order"`
}

// cfgResolveAll walks s and substitutes every $ref with the referenced $defs
// entry. A description on the referencing node overrides the def's description.
func cfgResolveAll(s *cfgSchema, defs map[string]*cfgSchema) *cfgSchema {
	if s == nil {
		return nil
	}

	result := *s

	if s.Ref != "" {
		name := strings.TrimPrefix(s.Ref, "#/$defs/")
		if def, ok := defs[name]; ok {
			merged := *def
			// annotations on the referencing node take precedence over the def
			if s.Description != "" {
				merged.Description = s.Description
			}
			if s.Order != nil {
				merged.Order = s.Order
			}
			result = merged
		}
	}

	if result.Properties != nil {
		resolved := make(map[string]*cfgSchema, len(result.Properties))
		for k, v := range result.Properties {
			resolved[k] = cfgResolveAll(v, defs)
		}
		result.Properties = resolved
	}
	result.AdditionalProperties = cfgResolveAll(result.AdditionalProperties, defs)
	result.Items = cfgResolveAll(result.Items, defs)

	for i, v := range result.OneOf {
		result.OneOf[i] = cfgResolveAll(v, defs)
	}
	for i, v := range result.AnyOf {
		result.AnyOf[i] = cfgResolveAll(v, defs)
	}

	return &result
}

// cfgTypeStr returns a human-readable type description for a schema node.
func cfgTypeStr(s *cfgSchema) string {
	if s == nil {
		return ""
	}

	if len(s.AnyOf) > 0 {
		parts := make([]string, 0, len(s.AnyOf))
		for _, v := range s.AnyOf {
			parts = append(parts, cfgTypeStr(v))
		}
		return strings.Join(parts, " or ")
	}

	if len(s.OneOf) > 0 {
		return "object"
	}

	if len(s.Type) == 0 {
		return ""
	}

	var t string
	if json.Unmarshal(s.Type, &t) == nil {
		return cfgFormatType(t, s)
	}

	var ts []string
	if json.Unmarshal(s.Type, &ts) == nil {
		parts := make([]string, len(ts))
		for i, each := range ts {
			parts[i] = cfgFormatType(each, s)
		}
		return strings.Join(parts, " or ")
	}

	return ""
}

func cfgFormatType(t string, s *cfgSchema) string {
	switch t {
	case "array":
		if s.Items != nil {
			return "array of " + cfgTypeStr(s.Items)
		}
		return "array"
	case "string":
		if s.MinLength != nil && *s.MinLength > 0 {
			return "string (non-empty)"
		}
		return "string"
	default:
		return t
	}
}

// cfgDefaultStr formats a raw JSON default value as a plain string.
func cfgDefaultStr(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	return string(raw)
}

// cfgIsRequired reports whether field is listed in s.Required.
func cfgIsRequired(s *cfgSchema, field string) bool {
	for _, r := range s.Required {
		if r == field {
			return true
		}
	}
	return false
}

// cfgConstraints returns human-readable constraint annotations.
func cfgConstraints(s *cfgSchema) []string {
	if s == nil {
		return nil
	}

	var out []string
	if s.Minimum != nil && s.Maximum != nil && *s.Minimum == *s.Maximum {
		out = append(out, fmt.Sprintf("must be `%v`", int(*s.Minimum)))
	} else {
		if s.Minimum != nil {
			out = append(out, fmt.Sprintf("minimum: `%v`", int(*s.Minimum)))
		}
		if s.Maximum != nil {
			out = append(out, fmt.Sprintf("maximum: `%v`", int(*s.Maximum)))
		}
	}
	return out
}

// propOrder returns the property keys of s sorted by x-order (when set),
// then required-before-optional, then alphabetically within each tier.
func propOrder(s *cfgSchema) []string {
	if s == nil {
		return nil
	}
	keys := make([]string, 0, len(s.Properties))
	for k := range s.Properties {
		keys = append(keys, k)
	}
	required := make(map[string]bool, len(s.Required))
	for _, r := range s.Required {
		required[r] = true
	}
	sort.Slice(keys, func(i, j int) bool {
		oi := orderNum(s.Properties[keys[i]])
		oj := orderNum(s.Properties[keys[j]])
		if oi != oj {
			return oi < oj
		}
		ri, rj := required[keys[i]], required[keys[j]]
		if ri != rj {
			return ri
		}
		return keys[i] < keys[j]
	})
	return keys
}

const noOrder = 1<<31 - 1

func orderNum(p *cfgSchema) int {
	if p != nil && p.Order != nil {
		return *p.Order
	}
	return noOrder
}
