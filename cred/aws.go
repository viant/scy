package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
)

//Aws represents AWS credentials
type (
	Aws struct {
		Endpoint        string      `json:",omitempty"`
		Region          string      `json:",omitempty"`
		Key             string      `json:",omitempty"` //KeyID
		Secret          string      `json:",omitempty"` //KeySecret
		Token           string      `json:",omitempty"`
		EncryptedSecret string      `json:",omitempty"`
		Session         *AwsSession `json:",omitempty"`
	}

	AwsSession struct {
		RoleArn string `json:",omitempty"`
		Name    string `json:",omitempty"`
	}
)

//Cipher ciphers password to encrypted password, clears password after that
func (b *Aws) Cipher(ctx context.Context, key *kms.Key) error {
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

//Decipher deciphers EncryptedPassword or returns error
func (b *Aws) Decipher(ctx context.Context, key *kms.Key) error {
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
		return fmt.Errorf("failed to decrypt EncryptedPassword: %w", err)
	}
	b.Secret = string(decrypted)
	b.EncryptedSecret = ""
	return nil
}
