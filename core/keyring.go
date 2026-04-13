package core

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"slices"
)

type Keyring interface {
	AddRecipient(user string, recp *Recipient)
	AddSignPubKey(user string, pub []byte)
	DeleteUser(user string) bool
	Verify(data []byte, signature string) (string, error)
	Recipients(users []string) Recipients
}

type MemoryKeyring struct {
	recipients map[string][]*Recipient
	signPubs   map[string][][]byte
}

func NewMemoryKeyring() *MemoryKeyring {
	return &MemoryKeyring{
		recipients: make(map[string][]*Recipient),
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
		return other.Equal(recp)
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
	return ok
}

func (mk *MemoryKeyring) verifySingle(key, data []byte, signature string) error {
	sigData, code, err := MulticodeDecode(signature)
	if err != nil {
		return err
	}

	if code != MhEdDSA {
		return fmt.Errorf("unexpected multihash code %d for signature, expected eddsa", code)
	}

	ok := ed25519.Verify(key, data, sigData)
	if !ok {
		return fmt.Errorf("could not validate signature '%s'", signature)
	}

	return nil
}

func (mk *MemoryKeyring) Verify(data []byte, signature string) (string, error) {
	// TODO: With rising number of signing keys htis will get a bit inefficient.
	//       With most uses we could probably hint at the right user.
	for user, signPubKeys := range mk.signPubs {
		for _, signPubKey := range signPubKeys {
			if err := mk.verifySingle(signPubKey, data, signature); err != nil {
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
