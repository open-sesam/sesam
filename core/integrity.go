package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/sha3"
)

// IntegrityError describes a single integrity issue found during deep verification.
type IntegrityError struct {
	// RevealedPath is the secret this error relates to, if any.
	RevealedPath string

	// Message describes the issue.
	Message string
}

// IntegrityReport collects all issues found during deep verification.
type IntegrityReport struct {
	Errors []IntegrityError
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
	sesamDir string,
	vs VerifiedSecret,
	report *IntegrityReport,
	diskSigMap map[string]*secretSignature,
	kr Keyring,
) {
	sig, hasSig := diskSigMap[vs.RevealedPath]
	defer delete(diskSigMap, vs.RevealedPath)

	if !hasSig {
		report.add(vs.RevealedPath, "missing .sesam file")
		return
	}

	sesamPath := filepath.Join(sesamDir, ".sesam", "objects", vs.RevealedPath+".sesam")

	//nolint:gosec
	fd, err := os.Open(sesamPath)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to open .sesam file: %v", err))
		return
	}

	defer closeLogged(fd)

	ageRd, _, err := readSignature(fd)
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

	if computedHash != sig.Hash {
		report.add(vs.RevealedPath, fmt.Sprintf(
			"hash mismatch: footer says %s, computed says %s",
			sig.Hash, computedHash,
		))
	}

	hashBytes, _, err := multicodeDecode(sig.Hash)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to decode hash: %v", err))
		return
	}

	if _, err := kr.Verify(SesamDomainSignSecretTag, hashBytes, sig.Signature, sig.SealedBy); err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("invalid signature: %v", err))
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
func VerifyIntegrity(sesamDir string, state *VerifiedState, kr Keyring) *IntegrityReport {
	report := &IntegrityReport{}

	diskSigs, err := readAllSignatures(sesamDir)
	if err != nil {
		report.add("", fmt.Sprintf("failed to read signatures: %v", err))
		return report
	}

	diskSigMap := make(map[string]*secretSignature, len(diskSigs))
	for idx := range diskSigs {
		diskSigMap[diskSigs[idx].RevealedPath] = &diskSigs[idx]
	}

	for _, vs := range state.Secrets {
		verifyIntegritySingleSecret(sesamDir, vs, report, diskSigMap, kr)
	}

	// Any remaining entries are .sesam files not tracked in the state.
	for path := range diskSigMap {
		report.add(path, "extra .sesam file not in verified state")
	}

	if state.LastSealRootHash != "" {
		sigPtrs := make([]*secretSignature, 0, len(diskSigs))
		for idx := range diskSigs {
			sigPtrs = append(sigPtrs, &diskSigs[idx])
		}

		diskRootHash := buildRootHash(sigPtrs)
		if diskRootHash != state.LastSealRootHash {
			report.add("", fmt.Sprintf(
				"root hash mismatch: log says %s, disk says %s",
				state.LastSealRootHash, diskRootHash,
			))
		}
	}

	return report
}
