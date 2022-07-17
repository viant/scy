package cred

import (
	"context"
	"fmt"
	"github.com/viant/scy/kms"
)

type RSA struct {
	KeyID               string `json:",omitempty"`
	Password            string `json:",omitempty"`
	EncryptedPassword   string `json:",omitempty"`
	PrivateKey          string `json:",omitempty"` //base64 encoded private
	PublicKey           string `json:",omitempty"` //base64 encoded public
	EncryptedPrivateKey string `json:",omitempty"` //base64 encoded private
	EncryptedPublicKey  string `json:",omitempty"` //base64 encoded public
}

//Cipher ciphers password to encrypted password, clears password after that
func (b *RSA) Cipher(ctx context.Context, key *kms.Key) error {
	if b.PrivateKey == "" {
		return fmt.Errorf("PrivateKey was empty")
	}
	if b.PublicKey == "" {
		return fmt.Errorf("PublicKey was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return fmt.Errorf("cipher failed to Lookup")
	}
	if err = encrypt(ctx, key, cipher, &b.PrivateKey, &b.EncryptedPrivateKey); err != nil {
		return fmt.Errorf("failed to encrypt private key; %w", err)
	}
	err = encrypt(ctx, key, cipher, &b.PublicKey, &b.EncryptedPublicKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt publicKey: %w", err)
	}

	if b.Password != "" {
		err = encrypt(ctx, key, cipher, &b.Password, &b.EncryptedPassword)
		if err != nil {
			return fmt.Errorf("failed to encrypt password: %w", err)
		}
	}

	return err
}

//Decipher deciphers EncryptedPassword or returns error
func (b *RSA) Decipher(ctx context.Context, key *kms.Key) error {
	if len(b.EncryptedPublicKey) == 0 {
		return fmt.Errorf("EncryptedPublicKey was empty")
	}
	if len(b.EncryptedPrivateKey) == 0 {
		return fmt.Errorf("EncryptedPrivateKey was empty")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return fmt.Errorf("decipher failed to Lookup")
	}
	if err = decrypt(ctx, key, cipher, &b.EncryptedPrivateKey, &b.PrivateKey); err != nil {
		return fmt.Errorf("failed to decrypt PrivateKey, %w", err)
	}
	if err = decrypt(ctx, key, cipher, &b.EncryptedPublicKey, &b.PublicKey); err != nil {
		return fmt.Errorf("failed to decrypt PublicKey: %w", err)
	}
	if b.EncryptedPassword != "" {
		err = encrypt(ctx, key, cipher, &b.EncryptedPassword, &b.Password)
		if err != nil {
			return fmt.Errorf("failed to decrypt password: %w", err)
		}
	}
	return nil
}
