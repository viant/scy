package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
	"os"
)

// SecretKey represents a key
type SecretKey struct {
	Key             string `json:",omitempty" yaml:"Key"`
	Secret          string `json:",omitempty" yaml:"Secret"`
	EncryptedSecret string `json:",omitempty" yaml:"EncryptedSecret"`
}

// SetEnv sets env
func (k *SecretKey) SetEnv() error {
	if k.Key == "" {
		return fmt.Errorf("key name was empty")
	}
	return os.Setenv(k.Key, k.Secret)
}

// Cipher ciphers password to encrypted password, clears password after that
func (b *SecretKey) Cipher(ctx context.Context, key *kms.Key) error {
	if b.Secret == "" {
		return fmt.Errorf("secret was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(ctx, key, []byte(b.Secret))
	if err == nil {
		var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
		base64.StdEncoding.Encode(base64Encoded, encrypted)
		b.EncryptedSecret = string(base64Encoded)
		b.Secret = ""
	}
	return err
}

// Decipher deciphers EncryptedSecret or returns error
func (b *SecretKey) Decipher(ctx context.Context, key *kms.Key) error {
	if len(b.EncryptedSecret) == 0 {
		if b.Secret != "" {
			return nil
		}
		return fmt.Errorf("encryptedSecret was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := base64.StdEncoding.DecodeString(b.EncryptedSecret)
	if err != nil {
		return err
	}
	decrypted, err := cipher.Decrypt(ctx, key, encrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt EncryptedSecret: %w", err)
	}
	b.Secret = string(decrypted)
	b.EncryptedSecret = ""
	return nil
}
