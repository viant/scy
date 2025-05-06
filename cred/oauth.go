package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
	"golang.org/x/oauth2"
)

type Oauth2Config struct {
	oauth2.Config
	EncryptedClientSecret string `json:",omitempty" yaml:"EncryptedSecret"`
}

// Cipher ciphers password to encrypted password, clears password after that
func (b *Oauth2Config) Cipher(ctx context.Context, key *kms.Key) error {
	if b.ClientSecret == "" {
		return fmt.Errorf("secret was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(ctx, key, []byte(b.ClientSecret))
	if err == nil {
		var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
		base64.StdEncoding.Encode(base64Encoded, encrypted)
		b.EncryptedClientSecret = string(base64Encoded)
		b.ClientSecret = ""
	}
	return err
}

// Decipher deciphers EncryptedSecret or returns error
func (b *Oauth2Config) Decipher(ctx context.Context, key *kms.Key) error {
	if len(b.EncryptedClientSecret) == 0 {
		if b.ClientSecret != "" {
			return nil
		}
		return fmt.Errorf("encryptedSecret was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := base64.StdEncoding.DecodeString(b.EncryptedClientSecret)
	if err != nil {
		return err
	}
	decrypted, err := cipher.Decrypt(ctx, key, encrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt EncryptedSecret: %w", err)
	}
	b.ClientSecret = string(decrypted)
	b.EncryptedClientSecret = ""
	return nil
}
