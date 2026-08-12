package xades

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// RevocationChecker validates revocation status without giving the XML parser
// implicit network access. Implementations may use stapled OCSP responses,
// caller-managed caches, CRLs, or an explicitly configured network client.
type RevocationChecker interface {
	Check(ctx context.Context, certificate, issuer *x509.Certificate, at time.Time) error
}

// TrustPolicy defines certificate-path validation independently of XMLDSig
// cryptographic validation. Roots must be supplied explicitly unless
// UseSystemRoots is set.
type TrustPolicy struct {
	Roots          *x509.CertPool
	Intermediates  *x509.CertPool
	UseSystemRoots bool
	KeyUsages      []x509.ExtKeyUsage
	DNSName        string
	Revocation     RevocationChecker
}

// TrustResult contains the verified paths selected by crypto/x509.
type TrustResult struct {
	Chains [][]*x509.Certificate
}

func (p *TrustPolicy) Verify(ctx context.Context, leaf *x509.Certificate, embedded []*x509.Certificate, at time.Time) (*TrustResult, error) {
	if p == nil {
		return nil, errors.New("trust policy is required")
	}
	if leaf == nil {
		return nil, errors.New("leaf certificate is required")
	}
	roots := p.Roots
	if roots == nil && p.UseSystemRoots {
		var err error
		roots, err = x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system certificate roots: %w", err)
		}
	}
	if roots == nil {
		return nil, errors.New("trust policy has no roots; configure Roots or UseSystemRoots")
	}
	intermediates := p.Intermediates
	if intermediates == nil {
		intermediates = x509.NewCertPool()
	}
	for _, certificate := range embedded {
		if certificate != nil && !certificate.Equal(leaf) {
			intermediates.AddCert(certificate)
		}
	}
	keyUsages := append([]x509.ExtKeyUsage(nil), p.KeyUsages...)
	if len(keyUsages) == 0 {
		keyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	chains, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   at,
		KeyUsages:     keyUsages,
		DNSName:       p.DNSName,
	})
	if err != nil {
		return nil, fmt.Errorf("verify signing certificate trust: %w", err)
	}
	if p.Revocation != nil {
		for _, chain := range chains {
			for index := 0; index+1 < len(chain); index++ {
				if err := p.Revocation.Check(ctx, chain[index], chain[index+1], at); err != nil {
					return nil, fmt.Errorf("verify revocation for certificate %q: %w", chain[index].Subject.String(), err)
				}
			}
		}
	}
	return &TrustResult{Chains: chains}, nil
}
