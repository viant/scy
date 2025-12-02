package signer

import (
	"context"

	"github.com/viant/scy"
)

// NewFromPEMKey initializes a signer from a raw RSA private key in PEM format.
func NewFromPEMKey(ctx context.Context, pem []byte) (*Service, error) {
	rsaRes := &scy.Resource{
		URL:  "inline://private.pem",
		Data: pem,
	}
	s := New(&Config{RSA: rsaRes})
	if err := s.Init(ctx); err != nil {
		return nil, err
	}
	return s, nil
}
