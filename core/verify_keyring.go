package core

// TODO: Double check that no public keys are re-used between users (should be forbidden) or are duplicated (just waste of computing)
// TODO: Check that users with forge-ids and links did not change (that's only for nice UX in case someone changes their github key but people forgot to re-key that user). If user does not exist anymore, then this is also worth knowing.

type SharedPublicKey struct {
	// PubKey is the string version of the key
	PubKey string

	// Users sharing this key.
	// If it's only a single user, then the key is listed more than once.
	Users []string
}

func VerifyKeyReuse(kr Keyring) []SharedPublicKey {
	userMap := kr.ListUsers()
	recpMap := make(map[string][]string)
	for user, recps := range userMap {
		for _, recp := range recps {
			recpStr := recp.String()
			recpMap[recpStr] = append(recpMap[recpStr], user)
		}
	}

	var results []SharedPublicKey
	for recpStr, users := range recpMap {
		if len(users) == 1 {
			continue
		}

		results = append(results, SharedPublicKey{
			PubKey: recpStr,
			Users:  users,
		})
	}

	return results
}

func VerifyForgeIds(vstate *VerifiedState, kr *Keyring) error {
	// TODO:
	//
	for _, user := range vstate.Users {
	}

	return nil
}
