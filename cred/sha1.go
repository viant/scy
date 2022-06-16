package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
)

//SHA1 represents sha1 key secrets
type SHA1 struct {
	Key                   string `json:",omitempty"`
	EncryptedKey          string `json:",omitempty"`
	IntegrityKey          string `json:",omitempty"`
	EncryptedIntegrityKey string `json:",omitempty"`
}

//Cipher ciphers password to encrypted password, clears password after that
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
	if err = b.encrypt(ctx, key, cipher, &b.Key, &b.EncryptedKey); err != nil {
		return fmt.Errorf("failed to encrypt key")
	}
	err = b.encrypt(ctx, key, cipher, &b.IntegrityKey, &b.EncryptedIntegrityKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt integrityKey")
	}
	return err
}

func (b *SHA1) encrypt(ctx context.Context, key *kms.Key, cipher kms.Cipher, value, encryptedValue *string) error {
	encryptedIntegrityKey, err := cipher.Encrypt(ctx, key, []byte(*value))
	if err != nil {
		return fmt.Errorf("failed to encrypt")
	}
	var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encryptedIntegrityKey)))
	base64.StdEncoding.Encode(base64Encoded, encryptedIntegrityKey)
	*encryptedValue = string(base64Encoded)
	*value = ""
	return nil
}

//Decipher deciphers EncryptedPassword or returns error
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
	if err = b.decrypt(ctx, key, cipher, &b.EncryptedKey, &b.Key); err != nil {
		return fmt.Errorf("failed to decrypt key")
	}
	if err = b.decrypt(ctx, key, cipher, &b.EncryptedIntegrityKey, &b.IntegrityKey); err != nil {
		return fmt.Errorf("failed to decrypt integrityKey")
	}

	return nil
}

func (b *SHA1) decrypt(ctx context.Context, key *kms.Key, cipher kms.Cipher, encryptedValue, value *string) error {
	encrypted, err := base64.StdEncoding.DecodeString(*encryptedValue)
	if err != nil {
		return fmt.Errorf("failed to decrypt DecodeString")
	}
	decrypted, err := cipher.Decrypt(ctx, key, encrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt")
	}
	*value = string(decrypted)
	*encryptedValue = ""
	return nil
}
