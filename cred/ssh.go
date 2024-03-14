package cred

import (
	"context"
	"encoding/base64"
	"github.com/viant/afs"
	assh "github.com/viant/scy/auth/ssh"
	"github.com/viant/scy/kms"
	"golang.org/x/crypto/ssh"
)

// SSH represents SSH config
type SSH struct {
	Basic
	PrivateKeyPath              string `json:",omitempty"`
	PrivateKey                  []byte `json:",omitempty"`
	PrivateKeyPassword          string `json:",omitempty"`
	EncryptedPrivateKeyPassword string `json:",omitempty"`
	EncryptedPrivateKey         string `json:",omitempty"`
}

func (s *SSH) Config(ctx context.Context) (*ssh.ClientConfig, error) {
	config := &ssh.ClientConfig{
		User:            s.Username,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // Note: In production, replace this with a proper host key callback
	}
	err := s.LoadPrivateKey(ctx)
	if err != nil {
		return nil, err
	}
	if len(s.PrivateKey) > 0 {
		authMethod, err := assh.LoadPrivateKeyWithPassphrase(s.PrivateKey, s.PrivateKeyPassword)
		if err != nil {
			return nil, err
		}
		config.Auth = append(config.Auth, authMethod)
	}
	if s.Password != "" {
		config.Auth = append(config.Auth, ssh.Password(s.Password))
	}
	return config, nil
}

func (s *SSH) LoadPrivateKey(ctx context.Context) error {
	if len(s.PrivateKey) > 0 || len(s.PrivateKeyPath) == 0 {
		return nil
	}

	fs := afs.New()
	data, err := fs.DownloadWithURL(ctx, s.PrivateKeyPath)
	if err != nil {
		return err
	}
	s.PrivateKey = data

	return nil
}

// Cipher ciphers sensitive data or error
func (b *SSH) Cipher(ctx context.Context, key *kms.Key) error {
	err := b.Basic.Cipher(ctx, key)
	if err != nil {
		return err
	}
	if err = b.cipherPrivateKeyPassword(ctx, key); err != nil {
		return err
	}
	if err = b.cipherPrivateKey(ctx, key); err != nil {
		return err
	}
	return err
}

func (b *SSH) cipherPrivateKey(ctx context.Context, key *kms.Key) error {
	if len(b.PrivateKey) == 0 {
		return nil
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	encrypted, err := cipher.Encrypt(ctx, key, b.PrivateKey)
	if err == nil {
		var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encrypted)))
		base64.StdEncoding.Encode(base64Encoded, encrypted)
		b.EncryptedPrivateKey = string(base64Encoded)
		b.Password = ""
	}
	return nil
}

func (b *SSH) cipherPrivateKeyPassword(ctx context.Context, key *kms.Key) error {
	if b.PrivateKeyPassword == "" || b.PrivateKeyPath != "" { //if location is specified do not encrypt key
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
	return nil
}

// Decipher deciphers sensitive data or error
func (b *SSH) Decipher(ctx context.Context, key *kms.Key) error {
	err := b.Basic.Decipher(ctx, key)
	if err != nil {
		return err
	}
	if err = b.decryptPrivateKeyPassword(ctx, key, err); err != nil {
		return err
	}
	if err = b.decryptPrivateKey(ctx, key, err); err != nil {
		return err
	}
	return nil
}

func (b *SSH) decryptPrivateKey(ctx context.Context, key *kms.Key, err error) error {
	if len(b.PrivateKey) > 0 || len(b.EncryptedPrivateKey) == 0 {
		return nil
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	decrypted, err := cipher.Decrypt(ctx, key, []byte(b.EncryptedPrivateKey))
	if err == nil {
		var base64Decoded = make([]byte, base64.StdEncoding.DecodedLen(len(decrypted)))
		_, err = base64.StdEncoding.Decode(base64Decoded, decrypted)
		if err != nil {
			return err
		}
		b.PrivateKey = decrypted
	}
	return nil
}

func (b *SSH) decryptPrivateKeyPassword(ctx context.Context, key *kms.Key, err error) error {
	if b.EncryptedPrivateKey == "" || b.PrivateKeyPassword != "" {
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
