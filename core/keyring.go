package core

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"
)

// Keyring is a collection of public keys (both for sign-verify and encryption)
type Keyring interface {
	// AddRecipient adds a recipient to `user`. It is the public part of a keypair
	// the user can use to encrypt files.
	AddRecipient(user string, recp *Recipient)

	// AddSignPubKey adds a signing key for a a specific user.
	// Most of the time a user has only a single key, except for key rotation.
	// For now, only ed25519 keys are supported in `pub`.
	AddSignPubKey(user string, pub []byte)

	// DeleteUser removes a user from they Keyring.
	// It will return true if the user existed.
	DeleteUser(user string) bool

	// Verify checks if `signature` fits to `data` using any of the signing keys.
	// `userHint` will test the sign keys of this user first. It may be empty.
	// The user that matched the signature is returned or an error.
	Verify(domain SignDomain, data []byte, signature string, userHint string) (string, error)

	// Recipients returns all recipients for a specific set of users.
	Recipients(users []string) Recipients

	// ListUsers() returns all users and recipients.
	ListUsers() map[string]Recipients
}

// MemoryKeyring is a simple Keyring implementation that holds public keys in memory only.
type MemoryKeyring struct {
	recipients map[string]Recipients
	signPubs   map[string][][]byte
}

func EmptyKeyring() *MemoryKeyring {
	return &MemoryKeyring{
		recipients: make(map[string]Recipients),
		signPubs:   make(map[string][][]byte),
	}
}

func (mk *MemoryKeyring) AddRecipient(user string, recp *Recipient) {
	recps, ok := mk.recipients[user]
	if !ok {
		mk.recipients[user] = []*Recipient{recp}
		return
	}

	if slices.ContainsFunc(recps, func(other *Recipient) bool {
		return other.Equal(recp.comparablePublicKey)
	}) {
		return
	}

	mk.recipients[user] = append(recps, recp)
}

func (mk *MemoryKeyring) AddSignPubKey(user string, key []byte) {
	signPubs, ok := mk.signPubs[user]
	if !ok {
		mk.signPubs[user] = [][]byte{key}
		return
	}

	if slices.ContainsFunc(signPubs, func(other []byte) bool {
		return bytes.Equal(other, key)
	}) {
		return
	}

	mk.signPubs[user] = append(mk.signPubs[user], key)
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

func (mk *MemoryKeyring) Verify(domain SignDomain, data []byte, signature string, userHint string) (string, error) {
	// With a large number of users it will be inefficient to iterate over all keys.
	// In most cases we know which user we expect to have made the signature.
	// In this case we can just hit this one first.
	if userHint != "" {
		signPubKeys, ok := mk.signPubs[userHint]
		if ok {
			for _, signPubKey := range signPubKeys {
				if err := mk.verifySingle(domain, signPubKey, data, signature); err != nil {
					continue
				}

				return userHint, nil
			}
		}
	}

	for user, signPubKeys := range mk.signPubs {
		if user == userHint {
			continue
		}

		for _, signPubKey := range signPubKeys {
			if err := mk.verifySingle(domain, signPubKey, data, signature); err != nil {
				continue
			}

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
