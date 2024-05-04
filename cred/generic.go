package cred

import (
	"context"
	"github.com/viant/scy/kms"
)

// Generic represents generic credentials
type Generic struct {
	SSH
	JwtConfig
	Aws
	Entry
}

func (g *Generic) Cipher(ctx context.Context, key *kms.Key) error {
	if g.Password != "" {
		if g.PrivateKeyPassword != "" {
			return g.SSH.Cipher(ctx, key)
		}
		return g.Basic.Cipher(ctx, key)
	}
	if g.Value != "" {
		return g.Entry.Cipher(ctx, key)
	}
	return nil
}

func (g *Generic) Decipher(ctx context.Context, key *kms.Key) error {
	if g.EncryptedPassword != "" {
		if g.EncryptedPrivateKeyPassword != "" {
			return g.SSH.Decipher(ctx, key)
		}
		return g.Basic.Decipher(ctx, key)
	}
	if g.EncryptedValue != "" {
		return g.Entry.Decipher(ctx, key)
	}
	return nil
}
