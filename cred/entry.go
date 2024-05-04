package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
	"os"
)

type Entry struct {
	Key            string `json:",omitempty"`
	Value          string `json:",omitempty"`
	EncryptedValue string `json:",omitempty"`
}

func (k *Entry) SetEnv() error {
	if k.Key == "" {
		return fmt.Errorf("key was empty")
	}
	return os.Setenv(k.Key, k.Value)
}

// Cipher ciphers password to encrypted password, clears password after that
func (k *Entry) Cipher(ctx context.Context, key *kms.Key) error {
	if k.Value == "" {
		return fmt.Errorf("phrase was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(ctx, key, []byte(k.Value))
	if err == nil {
		var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
		base64.StdEncoding.Encode(base64Encoded, encrypted)
		k.EncryptedValue = string(base64Encoded)
		k.Value = ""
	}
	return err
}

// Decipher deciphers EncryptedValue or returns error
func (k *Entry) Decipher(ctx context.Context, key *kms.Key) error {
	if len(k.EncryptedValue) == 0 {
		return fmt.Errorf("encryptedPassword was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := base64.StdEncoding.DecodeString(k.EncryptedValue)
	if err != nil {
		return err
	}
	decrypted, err := cipher.Decrypt(ctx, key, encrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt EncryptedValue: %w", err)
	}

	k.Value = string(decrypted)
	k.EncryptedValue = ""
	return nil
}
