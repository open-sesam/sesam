package config

import (
	"github.com/goccy/go-yaml/ast"
)

// UserKill removes a user from the main sesam.yml: the user's entry is cut from the
// users sequence and the user is dropped from every group's member list. A
// group left with no members is removed entirely (an empty member sequence has
// no valid block representation). Missing users are a no-op — the audit log
// (via the user manager) is the authority on whether the user exists; UserKill only
// keeps the YAML declaration in sync.
func (c *Config) UserKill(name string) error {
	src := c.MainFile

	dec, err := primedDecoder(src)
	if err != nil {
		return err
	}

	if seq, err := usersNode(src.RootNode); err == nil {
		for i := 0; i < len(seq.Values); {
			m, ok := seq.Values[i].(*ast.MappingNode)
			if ok {
				var u User
				if dec.DecodeFromNode(m, &u) == nil && u.Name == name {
					removeSeqValue(seq, i)
					continue // a value shifted into slot i
				}
			}
			i++
		}
	}

	if groups, err := groupsNode(src.RootNode); err == nil {
		for i := 0; i < len(groups.Values); {
			seq, shared := resolveMemberSeq(src.RootNode, groups.Values[i].Value)
			if seq == nil {
				i++
				continue
			}

			removed := removeMember(seq, name)
			if !removed {
				i++
				continue
			}

			if len(seq.Values) == 0 {
				if shared {
					// The sequence is an anchor definition or an alias to one,
					// so other groups may still reference it; dropping this
					// group's entry would either lose the anchor out from
					// under them or leave nothing to prune at all. Render it
					// as flow-style `[]` instead — goccy cannot render an
					// empty block sequence.
					seq.IsFlowStyle = true
					i++
					continue
				}
				// Sole owner of the sequence: drop the group we just emptied.
				groups.Values = append(groups.Values[:i], groups.Values[i+1:]...)
				continue
			}
			i++
		}
	}

	return nil
}

// resolveMemberSeq returns the *ast.SequenceNode backing a group's declared
// value, following an anchor definition or an alias reference to the anchor
// elsewhere in the document. shared is true whenever the sequence was reached
// through an anchor or alias, meaning it may be visible from other groups too
// and must not be deleted outright.
func resolveMemberSeq(root ast.Node, v ast.Node) (seq *ast.SequenceNode, shared bool) {
	switch n := v.(type) {
	case *ast.SequenceNode:
		return n, false
	case *ast.AnchorNode:
		seq, _ := n.Value.(*ast.SequenceNode)
		return seq, true
	case *ast.AliasNode:
		return resolveAlias(root, n), true
	default:
		return nil, false
	}
}

// resolveAlias returns the *ast.SequenceNode anchored under alias's name
// anywhere in root, or nil if none is found.
func resolveAlias(root ast.Node, alias *ast.AliasNode) *ast.SequenceNode {
	name := alias.Value.String()
	for _, n := range ast.Filter(ast.AnchorType, root) {
		anchor := n.(*ast.AnchorNode)
		if anchor.Name.String() != name {
			continue
		}
		if seq, ok := anchor.Value.(*ast.SequenceNode); ok {
			return seq
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
