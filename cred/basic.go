package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
)

// Basic represents basic credentials
type Basic struct {
	Endpoint          string `json:",omitempty"`
	Email             string `json:",omitempty"`
	Username          string `json:",omitempty"`
	Password          string `json:",omitempty"`
	EncryptedPassword string `json:",omitempty"`
}

// Cipher ciphers password to encrypted password, clears password after that
func (b *Basic) Cipher(ctx context.Context, key *kms.Key) error {
	if b.Password == "" {
		return fmt.Errorf("password was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(ctx, key, []byte(b.Password))
	if err == nil {
		var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
		base64.StdEncoding.Encode(base64Encoded, encrypted)
		b.EncryptedPassword = string(base64Encoded)
		b.Password = ""
	}
	return err
}

// Decipher deciphers EncryptedPassword or returns error
func (b *Basic) Decipher(ctx context.Context, key *kms.Key) error {
	if len(b.EncryptedPassword) == 0 {
		return fmt.Errorf("encryptedPassword was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := base64.StdEncoding.DecodeString(b.EncryptedPassword)
	if err != nil {
		return err
	}
	decrypted, err := cipher.Decrypt(ctx, key, encrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt EncryptedValue: %w", err)
	}

	b.Password = string(decrypted)
	b.EncryptedPassword = ""
	return nil
}
