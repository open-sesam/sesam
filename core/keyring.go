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
	// AddRecipient adds a recipient to `user`. It is the public part of a
	// keypair the user can use to encrypt files. `inserted` reports whether a
	// new key was stored: If it exists for `user` already it will be a no-op
	// (except adjusting the source). If `recp` is already used by any other
	// user, then DuplicatePubkeyError is returned.
	AddRecipient(user string, recp *Recipient) (inserted bool, err error)

	// RemoveRecipient removes the recipient `recp` from the recipients of `user`.
	// An error will be returned when there's only one recipient left and there's a match.
	// An error will be returned when there was no match.
	RemoveRecipient(user string, recp *Recipient) error

	// SetSignPubKey sets the signing key for a a specific user.
	// For now, only ed25519 keys are supported in `pub`.
	SetSignPubKey(user string, pub ed25519.PublicKey) error

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

	// Clone returns a deep copy of the keyring. It is used to snapshot the
	// keyring before audit-log replay so the contents can be restored on a
	// verification error (see Restore).
	Clone() Keyring

	// Restore replaces this keyring's contents with a deep copy of src's,
	// WITHOUT changing the keyring's identity. The repo and managers hold the
	// same *Keyring by pointer, so replay must roll back in place rather than
	// swap the pointer. src is typically a value previously returned by Clone.
	Restore(src Keyring)
}

// MemoryKeyring is a simple Keyring implementation that holds public keys in memory only.
type MemoryKeyring struct {
	recipients map[string]Recipients
	signPubs   map[string]ed25519.PublicKey
}

func EmptyKeyring() *MemoryKeyring {
	return &MemoryKeyring{
		recipients: make(map[string]Recipients),
		signPubs:   make(map[string]ed25519.PublicKey),
	}
}

func (mk *MemoryKeyring) AddRecipient(user string, recp *Recipient) (bool, error) {
	existingIdx := -1
	for existingUser, keys := range mk.recipients {
		for idx, other := range keys {
			if !other.Equal(recp) {
				continue
			}

			if existingUser != user {
				// another user already is using this key.
				return false, &DuplicatePubkeyError{
					user:   user,
					pubkey: fmt.Sprintf("%v", recp),
				}
			}

			existingIdx = idx
		}
	}

	if existingIdx >= 0 {
		// key already linked to this user: replace the entry so its source is
		// refreshed (e.g. manual -> github:x).
		mk.recipients[user][existingIdx] = recp
		return false, nil
	}

	mk.recipients[user] = append(mk.recipients[user], recp)
	return true, nil
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

func (mk *MemoryKeyring) SetSignPubKey(user string, newKey ed25519.PublicKey) error {
	// Reject only if *another* user already holds this key, so keys stay
	// unique across users (mirrors AddRecipient). Re-setting a user's own
	// key is allowed - replay re-applies init/tell entries into a populated
	// keyring, and a regen replaces the user's existing key in place.
	for existingUser, pubKey := range mk.signPubs {
		if existingUser != user && bytes.Equal(pubKey, newKey) {
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

// decodeSignPubKey decodes a multicode-encoded ed25519 signing public key,
// erroring out if the key is invalid (ed25519.Verify would crash on wrong length)
func decodeSignPubKey(encoded string) (ed25519.PublicKey, error) {
	raw, code, err := multicodeDecode(encoded)
	if err != nil {
		return nil, fmt.Errorf("bad signing key %q: %w", encoded, err)
	}

	if code != MhEd25519Pub {
		return nil, fmt.Errorf("unexpected multihash code %d for signing key, expected ed25519-pub", code)
	}

	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("signing key has unexpected length %d (want %d)", len(raw), ed25519.PublicKeySize)
	}

	return ed25519.PublicKey(raw), nil
}

func (mk *MemoryKeyring) verifySingle(domain SignDomain, key, data []byte, signature string) error {
	sigData, code, err := multicodeDecode(signature)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	if code != MhEdDSA {
		return fmt.Errorf("unexpected multihash code %d for signature, expected eddsa", code)
	}

	// ed25519.Verify panics on a wrong-length key
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length: %d", len(key))
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

func cloneRecipientsMap(in map[string]Recipients) map[string]Recipients {
	out := make(map[string]Recipients, len(in))
	for user, recps := range in {
		// *Recipient values are immutable after construction, so sharing the
		// pointers is safe; we only need an independent slice header.
		out[user] = slices.Clone(recps)
	}

	return out
}

func cloneSignPubs(in map[string]ed25519.PublicKey) map[string]ed25519.PublicKey {
	out := make(map[string]ed25519.PublicKey, len(in))
	for user, key := range in {
		// ed25519.PublicKey is a []byte; copy it so a later in-place change
		// cannot bleed into the snapshot.
		out[user] = slices.Clone(key)
	}

	return out
}

func (mk *MemoryKeyring) Clone() Keyring {
	return &MemoryKeyring{
		recipients: cloneRecipientsMap(mk.recipients),
		signPubs:   cloneSignPubs(mk.signPubs),
	}
}

func (mk *MemoryKeyring) Restore(src Keyring) {
	other, ok := src.(*MemoryKeyring)
	if !ok {
		panic(fmt.Sprintf("keyring restore: incompatible snapshot type %T", src))
	}

	// Deep copy so src stays independent and reusable after the restore.
	mk.recipients = cloneRecipientsMap(other.recipients)
	mk.signPubs = cloneSignPubs(other.signPubs)
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
