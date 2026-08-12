package cred

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/viant/afs"
	"github.com/viant/scy/auth/signing"
	"github.com/viant/scy/kms"
)

// Certificate represents an X.509 certificate bundle and its private key.
// Public certificate material is not encrypted; private key material and its
// password participate in Scy's kms.Securable lifecycle.
type Certificate struct {
	CertificatePath    string `json:",omitempty" yaml:",omitempty"`
	CertificatePEM     []byte `json:",omitempty" yaml:",omitempty"`
	PrivateKeyPath     string `json:",omitempty" yaml:",omitempty"`
	PrivateKeyPEM      []byte `json:",omitempty" yaml:",omitempty"`
	PrivateKeyPassword string `json:",omitempty" yaml:",omitempty"`

	EncryptedPrivateKey         string `json:",omitempty" yaml:",omitempty"`
	EncryptedPrivateKeyPassword string `json:",omitempty" yaml:",omitempty"`
}

// Identity loads and parses the credential into a certificate-backed signer.
func (c *Certificate) Identity(ctx context.Context) (*signing.Identity, error) {
	if err := c.Load(ctx); err != nil {
		return nil, err
	}
	return signing.NewIdentityPEM(c.CertificatePEM, c.PrivateKeyPEM, c.PrivateKeyPassword)
}

// Load downloads certificate or key material configured by path/URL.
func (c *Certificate) Load(ctx context.Context) error {
	fs := afs.New()
	if len(c.CertificatePEM) == 0 && c.CertificatePath != "" {
		data, err := fs.DownloadWithURL(ctx, c.CertificatePath)
		if err != nil {
			return fmt.Errorf("load certificate: %w", err)
		}
		c.CertificatePEM = data
	}
	if len(c.PrivateKeyPEM) == 0 && c.PrivateKeyPath != "" {
		data, err := fs.DownloadWithURL(ctx, c.PrivateKeyPath)
		if err != nil {
			return fmt.Errorf("load private key: %w", err)
		}
		c.PrivateKeyPEM = data
	}
	if len(c.CertificatePEM) == 0 {
		return errors.New("certificate PEM or path is required")
	}
	if len(c.PrivateKeyPEM) == 0 {
		return errors.New("private key PEM or path is required")
	}
	return nil
}

// Cipher encrypts inlined private key material and its password.
func (c *Certificate) Cipher(ctx context.Context, key *kms.Key) error {
	if key == nil {
		return errors.New("KMS key is required")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	if c.PrivateKeyPath != "" {
		// Keep only the external reference when serializing the credential.
		c.PrivateKeyPEM = nil
	} else if len(c.PrivateKeyPEM) > 0 {
		encrypted, err := cipher.Encrypt(ctx, key, c.PrivateKeyPEM)
		if err != nil {
			return fmt.Errorf("encrypt private key: %w", err)
		}
		c.EncryptedPrivateKey = base64.StdEncoding.EncodeToString(encrypted)
		c.PrivateKeyPEM = nil
	}
	if c.PrivateKeyPassword != "" {
		encrypted, err := cipher.Encrypt(ctx, key, []byte(c.PrivateKeyPassword))
		if err != nil {
			return fmt.Errorf("encrypt private key password: %w", err)
		}
		c.EncryptedPrivateKeyPassword = base64.StdEncoding.EncodeToString(encrypted)
		c.PrivateKeyPassword = ""
	}
	return nil
}

// Decipher restores encrypted private key material and its password.
func (c *Certificate) Decipher(ctx context.Context, key *kms.Key) error {
	if key == nil {
		return errors.New("KMS key is required")
	}
	cipher, err := kms.Lookup(key.Scheme)
	if err != nil {
		return err
	}
	if len(c.PrivateKeyPEM) == 0 && c.EncryptedPrivateKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.EncryptedPrivateKey)
		if err != nil {
			return fmt.Errorf("decode encrypted private key: %w", err)
		}
		c.PrivateKeyPEM, err = cipher.Decrypt(ctx, key, decoded)
		if err != nil {
			return fmt.Errorf("decrypt private key: %w", err)
		}
		c.EncryptedPrivateKey = ""
	}
	if c.PrivateKeyPassword == "" && c.EncryptedPrivateKeyPassword != "" {
		decoded, err := base64.StdEncoding.DecodeString(c.EncryptedPrivateKeyPassword)
		if err != nil {
			return fmt.Errorf("decode encrypted private key password: %w", err)
		}
		decrypted, err := cipher.Decrypt(ctx, key, decoded)
		if err != nil {
			return fmt.Errorf("decrypt private key password: %w", err)
		}
		c.PrivateKeyPassword = string(decrypted)
		c.EncryptedPrivateKeyPassword = ""
	}
	return nil
}
