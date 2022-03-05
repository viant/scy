package cred

import (
	"context"
	"encoding/base64"
	"github.com/viant/scy/kms"
)

//SSH represents SSH config
type SSH struct {
	Basic
	PrivateKeyPassword          string `json:",omitempty"`
	EncryptedPrivateKeyPassword string `json:",omitempty"`
}

//Cipher ciphers sensitive data or error
func (b *SSH) Cipher(ctx context.Context, key *kms.Key) error {
	err := b.Basic.Cipher(ctx, key)
	if err != nil {
		return err
	}
	if b.PrivateKeyPassword == "" {
		return nil
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(ctx, key, []byte(b.PrivateKeyPassword))
	if err == nil {
		var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
		base64.StdEncoding.Encode(base64Encoded, encrypted)
		b.EncryptedPrivateKeyPassword = string(base64Encoded)
		b.Password = ""
	}
	return err
}

//Decipher deciphers sensitive data or error
func (b *SSH) Decipher(ctx context.Context, key *kms.Key) error {
	err := b.Basic.Decipher(ctx, key)
	if err != nil {
		return err
	}
	if b.PrivateKeyPassword == "" {
		return nil
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	decrypted, err := cipher.Decrypt(ctx, key, []byte(b.EncryptedPrivateKeyPassword))
	if err == nil {
		var base64Decoded = make([]byte, base64.StdEncoding.DecodedLen(len(decrypted)))
		_, err = base64.StdEncoding.Decode(base64Decoded, decrypted)
		if err != nil {
			return err
		}
		b.PrivateKeyPassword = string(decrypted)
	}
	return nil
}
