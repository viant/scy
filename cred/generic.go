package cred

import (
	"context"
	"github.com/viant/scy/kms"
	"gopkg.in/yaml.v3"
)

// Generic represents generic credentials
type Generic struct {
	SSH
	JwtConfig
	Aws
}

// UnmarshalYAML preserves the flat credential representation used by Scy.
// yaml.v3 does not automatically flatten multiple anonymous structs, so each
// credential facet is decoded explicitly from the same mapping node.
func (g *Generic) UnmarshalYAML(value *yaml.Node) error {
	if err := value.Decode(&g.SSH); err != nil {
		return err
	}
	if err := value.Decode(&g.JwtConfig); err != nil {
		return err
	}
	if err := value.Decode(&g.Aws); err != nil {
		return err
	}
	// Basic is decoded last because yaml.v3 does not promote it through SSH's
	// anonymous embedding when multiple credential facets are present.
	return value.Decode(&g.Basic)
}

func (g *Generic) Cipher(ctx context.Context, key *kms.Key) error {
	if g.Password != "" {
		if g.PrivateKeyPassword != "" {
			return g.SSH.Cipher(ctx, key)
		}
		return g.Basic.Cipher(ctx, key)
	}
	if g.Secret != "" {
		return g.SecretKey.Cipher(ctx, key)
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
	if g.EncryptedSecret != "" {
		return g.SecretKey.Decipher(ctx, key)
	}
	return nil
}
