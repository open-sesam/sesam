package commands

import (
	"bytes"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/open-sesam/sesam/core"
)

func TestChooseInitIdentitySingle(t *testing.T) {
	identities := mustGenerateIdentities(t, 1)

	selected, err := chooseInitIdentity(identities, "identity.txt", strings.NewReader(""), &bytes.Buffer{}, true)
	if err != nil {
		t.Fatalf("chooseInitIdentity failed: %v", err)
	}

	if !selected.Public().Equal(identities[0].Public()) {
		t.Fatalf("expected first identity to be selected")
	}
}

func TestChooseInitIdentityInteractive(t *testing.T) {
	identities := mustGenerateIdentities(t, 2)
	out := &bytes.Buffer{}

	selected, err := chooseInitIdentity(identities, "identity.txt", strings.NewReader("2\n"), out, true)
	if err != nil {
		t.Fatalf("chooseInitIdentity failed: %v", err)
	}

	if !selected.Public().Equal(identities[1].Public()) {
		t.Fatalf("expected second identity to be selected")
	}

	if !strings.Contains(out.String(), "multiple identities found") {
		t.Fatalf("expected prompt warning, got: %q", out.String())
	}
}

func TestChooseInitIdentityNonInteractiveFails(t *testing.T) {
	identities := mustGenerateIdentities(t, 2)

	_, err := chooseInitIdentity(identities, "identity.txt", strings.NewReader(""), &bytes.Buffer{}, false)
	if err == nil {
		t.Fatal("expected error in non-interactive mode")
	}

	if !strings.Contains(err.Error(), "run init interactively") {
		t.Fatalf("expected interactive guidance error, got: %v", err)
	}
}

func mustGenerateIdentities(t *testing.T, n int) core.Identities {
	t.Helper()

	identities := make(core.Identities, 0, n)
	for range n {
		id, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatalf("failed to generate identity: %v", err)
		}

		parsed, err := core.ParseIdentity(id.String(), &core.StdinPassphraseProvider{})
		if err != nil {
			t.Fatalf("failed to parse identity: %v", err)
		}

		identities = append(identities, parsed)
	}

	return identities
}
