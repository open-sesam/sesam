package commands

import (
	"context"
	"fmt"
	"sort"
	"strings"

	clirepo "github.com/open-sesam/sesam/cli/repo"
	"github.com/open-sesam/sesam/core"
	"github.com/urfave/cli/v3"
)

// HandleVerify verifies repository audit and crypt state.
func HandleVerify(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	auditLog, keyring, vstate, err := loadVerifiedState(sesamDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLog.Close()
	}()

	if vstate.SealRequiredSeqID != 0 {
		fmt.Printf("verify ok (seal required after seq_id=%d)\n", vstate.SealRequiredSeqID)
		return nil
	}

	report := core.VerifyIntegrity(sesamDir, vstate, keyring)
	if !report.OK() {
		return fmt.Errorf("integrity check failed: %s", report.String())
	}

	fmt.Println("verify ok")
	return nil
}

// HandleID identifies the current user from configured identities.
func HandleID(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	auditLog, keyring, _, err := loadVerifiedState(sesamDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLog.Close()
	}()

	identities, err := loadIdentities(cmd.StringSlice("identity"), "sesam.identity.runtime")
	if err != nil {
		return err
	}

	whoami, _, err := identityToUser(identities, keyring.ListUsers())
	if err != nil {
		return fmt.Errorf("failed to identify current user: %w", err)
	}

	fmt.Println(whoami)
	return nil
}

// HandleServer starts the optional sesam API server.
func HandleServer(_ context.Context, _ *cli.Command) error {
	return handleStub("server")
}

// HandleLog prints audit-log history.
func HandleLog(_ context.Context, _ *cli.Command) error {
	return handleStub("log")
}

// HandleUndo reverts secret state to a prior revision.
func HandleUndo(_ context.Context, _ *cli.Command) error {
	return handleStub("undo")
}

// HandleListUsers lists users, groups, and access bindings.
func HandleListUsers(_ context.Context, cmd *cli.Command) error {
	sesamDir, err := clirepo.ResolveSesamDir(cmd.String("sesam-dir"))
	if err != nil {
		return err
	}

	auditLog, _, vstate, err := loadVerifiedState(sesamDir)
	if err != nil {
		return err
	}
	defer func() {
		_ = auditLog.Close()
	}()

	if len(vstate.Users) == 0 {
		fmt.Println("no users")
		return nil
	}

	users := append([]core.VerifiedUser(nil), vstate.Users...)
	sort.Slice(users, func(i, j int) bool {
		return users[i].Name < users[j].Name
	})

	for _, user := range users {
		groups := append([]string(nil), user.Groups...)
		sort.Strings(groups)
		fmt.Printf("%s\tgroups=%s\n", user.Name, commaJoined(groups))
	}

	return nil
}

// HandleApply applies config changes to audit and metadata state.
func HandleApply(_ context.Context, _ *cli.Command) error {
	return handleStub("apply")
}

func loadVerifiedState(sesamDir string) (*core.AuditLog, core.Keyring, *core.VerifiedState, error) {
	keyring := core.EmptyKeyring()
	auditLog, err := core.LoadAuditLog(sesamDir)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to load audit log: %w", err)
	}

	vstate, err := core.Verify(auditLog, keyring)
	if err != nil {
		_ = auditLog.Close()
		return nil, nil, nil, fmt.Errorf("failed to verify audit log: %w", err)
	}

	return auditLog, keyring, vstate, nil
}

func commaJoined(values []string) string {
	if len(values) == 0 {
		return ""
	}

	var out strings.Builder
	out.WriteString(values[0])
	for _, v := range values[1:] {
		out.WriteString(",")
		out.WriteString(v)
	}

	return out.String()
}
