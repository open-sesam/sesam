package core

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"
)

// DuplicatePubkeyError is returned when a key (recipient or signing key) is
// added for one user while another user already holds the same key. Keys must
// be unique across users so that `sesam id` can map a key back to a single user.
type DuplicatePubkeyError struct {
	user   string
	pubkey string
}

func (e *DuplicatePubkeyError) Error() string {
	return fmt.Sprintf("user %s already has recipient %s", e.user, e.pubkey)
}

// Keyring is a collection of public keys (both for sign-verify and encryption)
type Keyring interface {
	// AddRecipient adds a recipient to `user`. It is the public part of a keypair
	// the user can use to encrypt files. If `recp` is already linked to this ` user`
	// it is a no-op. If `recp` is already used by any other user, then DuplicatePubkeyError
	// is returned.
	AddRecipient(user string, recp *Recipient) error

	// TODO: comment.
	RemoveRecipient(user string, recp *Recipient) error

	// SetSignPubKey sets the signing key for a a specific user.
	// For now, only ed25519 keys are supported in `pub`.
	SetSignPubKey(user string, pub []byte) error

	// DeleteUser removes a user from they Keyring.
	// It will return true if the user existed.
	DeleteUser(user string) bool

	// Verify checks if `signature` fits to `data` using any of the signing keys.
	// `userHint` will test the sign keys of this user first. It may be empty.
	// The user that matched the signature is returned or an error.
	Verify(domain SignDomain, data []byte, signature, userHint string) (string, error)

	// Recipients returns all recipients for a specific set of users.
	Recipients(users []string) Recipients

	// ListUsers() returns all users and recipients.
	ListUsers() map[string]Recipients

	// RenameUser() renames existing oldUser to newUser.
	// If oldUser does not exists it's a no-op.
	RenameUser(oldUser, newUser string)
}

// MemoryKeyring is a simple Keyring implementation that holds public keys in memory only.
type MemoryKeyring struct {
	recipients map[string]Recipients
	signPubs   map[string][]byte
}

func EmptyKeyring() *MemoryKeyring {
	return &MemoryKeyring{
		recipients: make(map[string]Recipients),
		signPubs:   make(map[string][]byte),
	}
}

func (mk *MemoryKeyring) AddRecipient(user string, recp *Recipient) error {
	var isDuplicate bool
	for existingUser, keys := range mk.recipients {
		for _, other := range keys {
			if other.Equal(recp) {
				if user == existingUser {
					// key exists, but is just a duplicate of user.
					isDuplicate = true
					break
				}

				// another user already is using this key.
				return &DuplicatePubkeyError{
					user:   user,
					pubkey: fmt.Sprintf("%v", recp),
				}
			}
		}
	}

	if !isDuplicate {
		mk.recipients[user] = append(mk.recipients[user], recp)
	}

	return nil
}

func (mk *MemoryKeyring) RemoveRecipient(user string, toDelete *Recipient) error {
	recps, ok := mk.recipients[user]
	if !ok {
		return fmt.Errorf("no such user: %s", user)
	}

	idx := slices.IndexFunc(recps, func(o *Recipient) bool {
		return o.Equal(toDelete)
	})

	if idx < 0 {
		// key to delete did not exist.
		return fmt.Errorf("user %s has no key %s that we could remove", user, toDelete)
	}

	if len(recps) == 1 {
		// key was found, but it's the last one.
		return fmt.Errorf("user %s has only one key left, need to add new keys before removing further", user)
	}

	mk.recipients[user] = slices.Delete(recps, idx, idx+1)
	return nil
}

func (mk *MemoryKeyring) SetSignPubKey(user string, newKey []byte) error {
	// make sure there are no duplicates:
	for _, pubKey := range mk.signPubs {
		if bytes.Equal(pubKey, newKey) {
			return &DuplicatePubkeyError{
				user:   user,
				pubkey: fmt.Sprintf("%v", newKey),
			}
		}
	}

	mk.signPubs[user] = newKey
	return nil
}

func (mk *MemoryKeyring) DeleteUser(user string) bool {
	_, ok := mk.recipients[user]
	delete(mk.recipients, user)
	delete(mk.signPubs, user)
	return ok
}

func (mk *MemoryKeyring) verifySingle(domain SignDomain, key, data []byte, signature string) error {
	sigData, code, err := multicodeDecode(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if code != MhEdDSA {
		return fmt.Errorf("unexpected multihash code %d for signature, expected eddsa", code)
	}

	ok := ed25519.Verify(key, append(domain, data...), sigData)
	if !ok {
		return fmt.Errorf("could not validate signature '%s'", signature)
	}

	return nil
}

func (mk *MemoryKeyring) Verify(domain SignDomain, data []byte, signature, userHint string) (string, error) {
	// With a large number of users it will be inefficient to iterate over all keys.
	// In most cases we know which user we expect to have made the signature.
	// In this case we can just hit this one first.
	if userHint != "" {
		signPubKey, ok := mk.signPubs[userHint]
		if ok {
			if err := mk.verifySingle(domain, signPubKey, data, signature); err == nil {
				return userHint, nil
			}
		}
	}

	for user, signPubKey := range mk.signPubs {
		if user == userHint {
			continue
		}

		if err := mk.verifySingle(domain, signPubKey, data, signature); err == nil {
			return user, nil
		}
	}

	return "", fmt.Errorf("no matching signature key found")
}

func (mk *MemoryKeyring) Recipients(users []string) Recipients {
	recps := make(Recipients, 0, 1)
	for _, user := range users {
		recps = append(recps, mk.recipients[user]...)
	}

	return recps
}

func (mk *MemoryKeyring) ListUsers() map[string]Recipients {
	return mk.recipients
}

// AllRecipients returns all active recipients known in the system
func AllRecipients(kr Keyring) Recipients {
	var recps Recipients
	for _, userRecps := range kr.ListUsers() {
		recps = append(recps, userRecps...)
	}

	return recps
}

func (mk *MemoryKeyring) RenameUser(oldUser, newUser string) {
	recps, ok1 := mk.recipients[oldUser]
	signPubs, ok2 := mk.signPubs[oldUser]
	if !ok1 || !ok2 {
		return
	}

	delete(mk.recipients, oldUser)
	mk.recipients[newUser] = recps

	delete(mk.signPubs, oldUser)
	mk.signPubs[newUser] = signPubs
}
