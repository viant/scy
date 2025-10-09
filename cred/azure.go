package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
)

// Azure represents Azure OAuth2 configuration
// ClientSecret is optional for public clients; when empty, Cipher/Decipher are no-ops.
type Azure struct {
	Oauth2Config
	TenantID string `json:"tenantId" yaml:"tenantId"`
}

// Cipher encrypts ClientSecret when present and clears it.
func (b *Azure) Cipher(ctx context.Context, key *kms.Key) error {
	if b.ClientSecret == "" { // secret is optional
		return nil
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

// Decipher decrypts EncryptedClientSecret when present.
func (b *Azure) Decipher(ctx context.Context, key *kms.Key) error {
	if len(b.EncryptedClientSecret) == 0 { // secret is optional
		return nil
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
