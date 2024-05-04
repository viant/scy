package cred

import (
	"context"
	"fmt"
	"github.com/viant/scy/kms"
)

// SHA1 represents sha1 key secrets
type SHA1 struct {
	Key                   string `json:",omitempty"`
	EncryptedKey          string `json:",omitempty"`
	IntegrityKey          string `json:",omitempty"`
	EncryptedIntegrityKey string `json:",omitempty"`
}

// Cipher ciphers password to encrypted password, clears password after that
func (b *SHA1) Cipher(ctx context.Context, key *kms.Key) error {
	if b.Key == "" {
		return fmt.Errorf("key was empty")
	}
	if b.IntegrityKey == "" {
		return fmt.Errorf("integrityKey was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return fmt.Errorf("cipher failed to Lookup")
	}
	if err = encrypt(ctx, key, cipher, &b.Key, &b.EncryptedKey); err != nil {
		return fmt.Errorf("failed to encrypt key")
	}
	err = encrypt(ctx, key, cipher, &b.IntegrityKey, &b.EncryptedIntegrityKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt integrityKey")
	}
	return err
}

// Decipher deciphers EncryptedSecret or returns error
func (b *SHA1) Decipher(ctx context.Context, key *kms.Key) error {
	if len(b.EncryptedKey) == 0 {
		return fmt.Errorf("encryptedKey was empty")
	}
	if len(b.EncryptedIntegrityKey) == 0 {
		return fmt.Errorf("encryptedIntegrityKey was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return fmt.Errorf("decipher failed to Lookup")
	}
	if err = decrypt(ctx, key, cipher, &b.EncryptedKey, &b.Key); err != nil {
		return fmt.Errorf("failed to decrypt key")
	}
	if err = decrypt(ctx, key, cipher, &b.EncryptedIntegrityKey, &b.IntegrityKey); err != nil {
		return fmt.Errorf("failed to decrypt integrityKey")
	}
	return nil
}
