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

func (ie IntegrityError) Error() string {
	if ie.RevealedPath != "" {
		return fmt.Sprintf("%s: %s", ie.RevealedPath, ie.Message)
	}

	return ie.Message
}

// IntegrityReport collects all issues found during deep verification.
type IntegrityReport struct {
	Errors []IntegrityError
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

func (ir *IntegrityReport) Error() string {
	if ir.OK() {
		return "no issues"
	}

	msg := fmt.Sprintf("%d integrity issue(s):", len(ir.Errors))
	for _, e := range ir.Errors {
		msg += "\n  - " + e.Error()
	}

	return msg
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
	diskSigs, err := ReadAllSignatures(repoDir)
	if err != nil {
		report.add("", fmt.Sprintf("failed to read signatures: %v", err))
		return report
	}

	diskSigMap := make(map[string]*SecretSignature, len(diskSigs))
	for i := range diskSigs {
		diskSigMap[diskSigs[i].RevealedPath] = &diskSigs[i]
	}

	// Collect all .age files on disk to detect extras.
	diskAgeFiles := collectAgeFiles(repoDir)

	// Check every secret in the verified state.
	for _, vs := range state.Secrets {
		sig, hasSig := diskSigMap[vs.RevealedPath]
		if !hasSig {
			report.add(vs.RevealedPath, "missing .sig.json file")
		}

		// Check .age file exists and hash matches.
		agePath := filepath.Join(repoDir, ".sesam", "objects", vs.RevealedPath+".age")
		ageFd, err := os.Open(agePath)
		if err != nil {
			report.add(vs.RevealedPath, fmt.Sprintf("missing .age file: %v", err))
			delete(diskSigMap, vs.RevealedPath)
			delete(diskAgeFiles, vs.RevealedPath)
			continue
		}

		h := sha3.New256()
		if _, err := io.Copy(h, ageFd); err != nil {
			report.add(vs.RevealedPath, fmt.Sprintf("failed to hash .age file: %v", err))
			closeLogged(ageFd)
			delete(diskSigMap, vs.RevealedPath)
			delete(diskAgeFiles, vs.RevealedPath)
			continue
		}
		closeLogged(ageFd)

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
			hashBytes, _, err := MulticodeDecode(sig.Hash)
			if err != nil {
				report.add(vs.RevealedPath, fmt.Sprintf("failed to decode hash: %v", err))
			} else if _, err := kr.Verify(hashBytes, sig.Signature, sig.SealedBy); err != nil {
				report.add(vs.RevealedPath, fmt.Sprintf("invalid signature: %v", err))
			}
		}

		// Remove from maps so we can detect extras.
		delete(diskSigMap, vs.RevealedPath)
		delete(diskAgeFiles, vs.RevealedPath)
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
		sigPtrs := make([]*SecretSignature, 0, len(diskSigs))
		for i := range diskSigs {
			sigPtrs = append(sigPtrs, &diskSigs[i])
		}

		diskRootHash := BuildRootHash(sigPtrs)
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
			return nil
		}

		rel, err := filepath.Rel(objectsDir, path)
		if err != nil {
			return nil
		}

		revealedPath := strings.TrimSuffix(rel, ".age")
		result[revealedPath] = true
		return nil
	})

	return result
}
