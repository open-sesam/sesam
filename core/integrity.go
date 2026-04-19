package core

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

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
	repoDir string,
	vs VerifiedSecret,
	report *IntegrityReport,
	diskAgeFiles map[string]bool,
	diskSigMap map[string]*secretSignature,
	kr Keyring,
) {
	sig, hasSig := diskSigMap[vs.RevealedPath]
	if !hasSig {
		report.add(vs.RevealedPath, "missing .sig.json file")
	}

	// Remove from maps so we can detect extras.
	defer delete(diskSigMap, vs.RevealedPath)
	defer delete(diskAgeFiles, vs.RevealedPath)

	// Check .age file exists and hash matches.
	agePath := filepath.Join(repoDir, ".sesam", "objects", vs.RevealedPath+".age")

	//nolint:gosec
	ageFd, err := os.Open(agePath)
	if err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("missing .age file: %v", err))
		return
	}

	defer closeLogged(ageFd)

	h := sha3.New256()
	if _, err := io.Copy(h, ageFd); err != nil {
		report.add(vs.RevealedPath, fmt.Sprintf("failed to hash .age file: %v", err))
		return
	}

	_, _ = h.Write([]byte(vs.RevealedPath))
	computedHash := MulticodeEncode(h.Sum(nil), MhSHA3_256)

	if hasSig && computedHash != sig.Hash {
		report.add(vs.RevealedPath, fmt.Sprintf(
			"hash mismatch: .sig.json says %s, .age file says %s",
			sig.Hash, computedHash,
		))
	}

	// Verify the signature in .sig.json.
	if hasSig {
		hashBytes, _, err := multicodeDecode(sig.Hash)
		if err != nil {
			report.add(vs.RevealedPath, fmt.Sprintf("failed to decode hash: %v", err))
		} else if _, err := kr.Verify(
			SesamDomainSignSecretTag,
			hashBytes,
			sig.Signature,
			sig.SealedBy,
		); err != nil {
			report.add(vs.RevealedPath, fmt.Sprintf("invalid signature: %v", err))
		}
	}
}

// VerifyIntegrity performs a deep integrity check comparing the verified state
// against the actual files on disk. It checks:
//
//   - Every secret in the state has a .sig.json and .age file on disk.
//   - The .age file hash matches the hash in .sig.json.
//   - The signature in .sig.json is valid.
//   - No extra .sig.json or .age files exist that are not in the state.
//   - The RootHash from the latest seal matches.
//
// All errors are collected, not returned early.
func VerifyIntegrity(repoDir string, state *VerifiedState, kr Keyring) *IntegrityReport {
	report := &IntegrityReport{}

	// Read all .sig.json files from disk.
	diskSigs, err := readAllSignatures(repoDir)
	if err != nil {
		report.add("", fmt.Sprintf("failed to read signatures: %v", err))
		return report
	}

	diskSigMap := make(map[string]*secretSignature, len(diskSigs))
	for idx := range diskSigs {
		diskSigMap[diskSigs[idx].RevealedPath] = &diskSigs[idx]
	}

	// Collect all .age files on disk to detect extras.
	diskAgeFiles := collectAgeFiles(repoDir)

	// Check every secret in the verified state.
	for _, vs := range state.Secrets {
		verifyIntegritySingleSecret(repoDir, vs, report, diskAgeFiles, diskSigMap, kr)
	}

	// Any remaining entries are files not tracked in the state.
	for path := range diskSigMap {
		report.add(path, "extra .sig.json file not in verified state")
	}

	for path := range diskAgeFiles {
		report.add(path, "extra .age file not in verified state")
	}

	// RootHash check ties it all together.
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

// collectAgeFiles walks .sesam/objects/ and returns a map of revealedPath -> true
// for every .age file found.
func collectAgeFiles(repoDir string) map[string]bool {
	objectsDir := filepath.Join(repoDir, ".sesam", "objects")
	result := make(map[string]bool)

	_ = filepath.WalkDir(objectsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".age") {
			//nolint:nilerr
			return nil
		}

		rel, err := filepath.Rel(objectsDir, path)
		if err != nil {
			//nolint:nilerr
			return nil
		}

		revealedPath := strings.TrimSuffix(rel, ".age")
		result[revealedPath] = true
		return nil
	})

	return result
}
