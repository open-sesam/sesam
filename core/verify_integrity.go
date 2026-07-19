package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/crypto/sha3"
)

// IntegrityError describes a single integrity issue found during deep verification.
type IntegrityError struct {
	// RevealedPath is the secret this error relates to, if any.
	RevealedPath string `json:"revealed_path"`

	// Message describes the issue.
	Message string `json:"message"`
}

// IntegrityReport collects all issues found during deep verification.
type IntegrityReport struct {
	Errors []IntegrityError `json:"errors,omitempty"`
}

func (ir *IntegrityReport) IsZero() bool {
	return len(ir.Errors) == 0
}

func (ie IntegrityError) Error() string {
	if ie.RevealedPath != "" {
		return fmt.Sprintf("%s: %s", ie.RevealedPath, ie.Message)
	}

	return ie.Message
}

func (ir *IntegrityReport) add(path, msg string) {
	ir.Errors = append(ir.Errors, IntegrityError{
		RevealedPath: path,
		Message:      msg,
	})
}

func (ir *IntegrityReport) OK() bool {
	return len(ir.Errors) == 0
}

func (ir *IntegrityReport) String() string {
	if ir.OK() {
		return "no issues"
	}

	msg := fmt.Sprintf("%d integrity issue(s):", len(ir.Errors))
	for _, e := range ir.Errors {
		msg += "\n  - " + e.Error()
	}

	return msg
}

func verifyIntegritySingleSecret(
	root *os.Root,
	vs VerifiedSecret,
	report *IntegrityReport,
	diskSigMap map[string]*secretFooter,
	kr Keyring,
	state *VerifiedState,
) {
	sig, hasSig := diskSigMap[vs.RevealedPath]
	defer delete(diskSigMap, vs.RevealedPath)

	if !hasSig {
		report.add(vs.RevealedPath, "missing .sesam file")
		return
	}

	sesamPath := filepath.Join(".sesam", "objects", vs.RevealedPath+".sesam")

	fd, err := root.Open(sesamPath)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to open .sesam file: %v", err))
		return
	}

	defer closeLogged(fd)

	ageRd, _, err := readFooter(fd)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to read .sesam footer: %v", err))
		return
	}

	h := sha3.New256()
	if _, err := io.Copy(h, ageRd); err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to hash .sesam file: %v", err))
		return
	}

	_, _ = h.Write([]byte(vs.RevealedPath))
	computedHash := MulticodeEncode(h.Sum(nil), MhSHA3_256)

	if computedHash != sig.CipherTextHash {
		report.add(vs.RevealedPath, fmt.Sprintf(
			"hash mismatch: footer says %s, computed says %s",
			sig.CipherTextHash, computedHash,
		))
	}

	cipherTextHashBytes, _, err := multicodeDecode(sig.CipherTextHash)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to decode ciphertext hash: %v", err))
		return
	}

	hmacContentHashBytes, _, err := multicodeDecode(sig.HMACContentHash)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to decode content hash: %v", err))
		return
	}

	recipientsHashBytes, _, err := multicodeDecode(sig.RecipientsHash)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to decode recipients hash: %v", err))
		return
	}

	sealer, err := kr.Verify(
		SesamDomainSignSecretTag,
		slices.Concat(cipherTextHashBytes, hmacContentHashBytes, recipientsHashBytes),
		sig.Signature,
		sig.SealedBy,
	)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("invalid signature: %v", err))
		return
	}

	if !state.SealerAuthorized(sealer, vs.RevealedPath) {
		report.add(vs.RevealedPath, fmt.Sprintf(
			"sealer %s is not authorized to seal this secret", sealer,
		))
	}
}

// VerifyIntegrity performs a deep integrity check comparing the verified state
// against the actual files on disk. It checks:
//
//   - Every secret in the state has a .sesam file on disk.
//   - The age ciphertext hash matches the hash in the footer.
//   - The footer signature is valid.
//   - No extra .sesam files exist that are not in the state.
//   - The RootHash from the latest seal matches.
//
// All errors are collected, not returned early.
func VerifyIntegrity(root *os.Root, state *VerifiedState, kr Keyring) *IntegrityReport {
	report := &IntegrityReport{}

	diskSigs, err := readAllSignatures(root)
	if err != nil {
		report.add("", fmt.Sprintf("failed to read signatures: %v", err))
		return report
	}

	diskSigMap := make(map[string]*secretFooter, len(diskSigs))
	for _, sig := range diskSigs {
		diskSigMap[sig.RevealedPath] = sig
	}

	for _, vs := range state.Secrets {
		verifyIntegritySingleSecret(root, vs, report, diskSigMap, kr, state)
	}

	// Any remaining entries are .sesam files not tracked in the state.
	for path := range diskSigMap {
		report.add(path, "extra .sesam file not in verified state")
	}

	if state.LastSealRootHash != "" {
		diskRootHash := buildRootHash(diskSigs)
		if diskRootHash != state.LastSealRootHash {
			report.add("", fmt.Sprintf(
				"root hash mismatch: log says %s, disk says %s",
				state.LastSealRootHash, diskRootHash,
			))
		}
	}

	return report
}
