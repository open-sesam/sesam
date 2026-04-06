package core

import (
	"encoding/json"
	"fmt"
)

func Verify(log *AuditLog) error {
	// TODO: need to verify that previous logs are a prefix of this one here.

	var previousEntry *AuditEntrySigned
	err := log.Iterate(func(idx int, entry *AuditEntrySigned) error {
		// check the signature
		if err := entry.Verify(log.Signer); err != nil {
			return fmt.Errorf("failed to verify signature on entry %d: %w", idx, err)
		}

		if previousEntry != nil {
			prevJSON, err := json.Marshal(previousEntry)
			if err != nil {
				return fmt.Errorf("marshal previous entry: %w", err)
			}

			expectedHash := Hash(prevJSON)
			if expectedHash != entry.PreviousHash {
				return fmt.Errorf(
					"broken chain at idx %d: %s != %s",
					idx,
					expectedHash,
					entry.PreviousHash,
				)
			}
		}

		switch entry.Operation {
		case OpInit:
			if entry.SeqID != 1 {
				return fmt.Errorf("init at wrong seq_id: %d (!= 1)", entry.SeqID)
			}
		case OpUserTell:
			tellDetails, err := ParseDetail[DetailUserTell](entry)
			if err != nil {
				return err
			}

			_ = tellDetails // TODO: do the actual verification.
		case OpSeal:
			sealDetails, err := ParseDetail[DetailSeal](entry)
			if err != nil {
				return fmt.Errorf("parse detail: %w", err)
			}

			_ = sealDetails // TODO: do the actual verification.
		}

		previousEntry = entry
		return nil
	})
	if err != nil {
		return err
	}

	return nil
}
