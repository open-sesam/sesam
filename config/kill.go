package config

import (
	"github.com/goccy/go-yaml"
	"github.com/goccy/go-yaml/ast"
)

// Kill removes a user from the main sesam.yml: the user's entry is cut from the
// users sequence and the user is dropped from every group's member list. A
// group left with no members is removed entirely (an empty member sequence has
// no valid block representation). Missing users are a no-op — the audit log
// (via the user manager) is the authority on whether the user exists; Kill only
// keeps the YAML declaration in sync.
func (c *Config) Kill(name string) error {
	src := c.MainFile

	if seq, err := usersNode(src.RootNode); err == nil {
		for i := 0; i < len(seq.Values); {
			m, ok := seq.Values[i].(*ast.MappingNode)
			if ok {
				var u User
				if yaml.NodeToValue(m, &u) == nil && u.Name == name {
					removeSeqValue(seq, i)
					continue // a value shifted into slot i
				}
			}
			i++
		}
	}

	if groups, err := groupsNode(src.RootNode); err == nil {
		for i := 0; i < len(groups.Values); {
			seq, ok := groups.Values[i].Value.(*ast.SequenceNode)
			if !ok {
				i++
				continue
			}

			removed := removeMember(seq, name)
			if removed && len(seq.Values) == 0 {
				// Drop the group we just emptied; goccy cannot render an empty
				// block sequence ("group:\n[]" is invalid).
				groups.Values = append(groups.Values[:i], groups.Values[i+1:]...)
				continue
			}
			i++
		}
	}

	return nil
}

// removeMember cuts every occurrence of name from a group's member sequence,
// reporting whether anything was removed.
func removeMember(seq *ast.SequenceNode, name string) bool {
	removed := false
	for i := 0; i < len(seq.Values); {
		if seq.Values[i].GetToken().Value == name {
			removeSeqValue(seq, i)
			removed = true
			continue
		}
		i++
	}
	return removed
}
