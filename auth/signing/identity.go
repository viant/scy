package signing

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Identity binds a private-key signer to its leaf certificate and optional
// certificate chain. Signer may be backed by software, a smart card, an HSM,
// or a cloud KMS as long as it implements crypto.Signer.
type Identity struct {
	Signer      crypto.Signer
	Certificate *x509.Certificate
	Chain       []*x509.Certificate
}

// NewIdentity validates and returns a certificate-backed signer identity.
func NewIdentity(signer crypto.Signer, certificate *x509.Certificate, chain ...*x509.Certificate) (*Identity, error) {
	identity := &Identity{Signer: signer, Certificate: certificate, Chain: chain}
	if err := identity.Validate(time.Time{}); err != nil {
		return nil, err
	}
	return identity, nil
}

// NewIdentityPEM parses a PEM certificate bundle and a PEM private key.
// PKCS#1 RSA, SEC1 EC, and unencrypted PKCS#8 keys are supported. Legacy
// PEM encryption is supported when password is supplied.
func NewIdentityPEM(certificatePEM, privateKeyPEM []byte, password string) (*Identity, error) {
	certificates, err := ParseCertificatesPEM(certificatePEM)
	if err != nil {
		return nil, err
	}
	signer, err := ParsePrivateKeyPEM(privateKeyPEM, password)
	if err != nil {
		return nil, err
	}
	return NewIdentity(signer, certificates[0], certificates[1:]...)
}

// Validate checks that the signer and certificate are present, use the same
// public key, and, when at is non-zero, that the certificate is time-valid.
// It intentionally does not establish trust; callers choose their trust roots.
func (i *Identity) Validate(at time.Time) error {
	if i == nil || i.Signer == nil {
		return errors.New("signing identity has no signer")
	}
	if i.Certificate == nil {
		return errors.New("signing identity has no certificate")
	}
	certPublic, err := x509.MarshalPKIXPublicKey(i.Certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("marshal certificate public key: %w", err)
	}
	signerPublic, err := x509.MarshalPKIXPublicKey(i.Signer.Public())
	if err != nil {
		return fmt.Errorf("marshal signer public key: %w", err)
	}
	if !bytes.Equal(certPublic, signerPublic) {
		return errors.New("private key does not match certificate")
	}
	if !at.IsZero() && (at.Before(i.Certificate.NotBefore) || at.After(i.Certificate.NotAfter)) {
		return fmt.Errorf("certificate is not valid at %s", at.UTC().Format(time.RFC3339))
	}
	if i.Certificate.KeyUsage != 0 && i.Certificate.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errors.New("certificate does not permit digital signatures")
	}
	return nil
}

// CertificateChainDER returns the leaf certificate followed by its chain.
func (i *Identity) CertificateChainDER() [][]byte {
	if i == nil || i.Certificate == nil {
		return nil
	}
	result := make([][]byte, 0, 1+len(i.Chain))
	result = append(result, append([]byte(nil), i.Certificate.Raw...))
	for _, certificate := range i.Chain {
		if certificate != nil {
			result = append(result, append([]byte(nil), certificate.Raw...))
		}
	}
	return result
}

// ParseCertificatesPEM parses all CERTIFICATE blocks in a PEM bundle.
func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var result []*x509.Certificate
	for len(data) > 0 {
		block, rest := pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if block.Type != "CERTIFICATE" {
			continue
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse certificate: %w", err)
		}
		result = append(result, certificate)
	}
	if len(result) == 0 {
		return nil, errors.New("certificate PEM contains no CERTIFICATE block")
	}
	return result, nil
}

// ParsePrivateKeyPEM parses a private key and returns it as crypto.Signer.
func ParsePrivateKeyPEM(data []byte, password string) (crypto.Signer, error) {
	var block *pem.Block
	for len(data) > 0 {
		var rest []byte
		block, rest = pem.Decode(data)
		if block == nil {
			break
		}
		data = rest
		if strings.Contains(block.Type, "PRIVATE KEY") {
			break
		}
		block = nil
	}
	if block == nil {
		return nil, errors.New("private-key PEM contains no key block")
	}
	keyDER := block.Bytes
	if x509.IsEncryptedPEMBlock(block) { //nolint:staticcheck // legacy PEM remains common in certificate exports.
		if password == "" {
			return nil, errors.New("private key is encrypted but no password was supplied")
		}
		var err error
		keyDER, err = x509.DecryptPEMBlock(block, []byte(password)) //nolint:staticcheck
		if err != nil {
			return nil, fmt.Errorf("decrypt private key: %w", err)
		}
	}

	parsers := []func([]byte) (any, error){
		func(der []byte) (any, error) { return x509.ParsePKCS8PrivateKey(der) },
		func(der []byte) (any, error) { return x509.ParsePKCS1PrivateKey(der) },
		func(der []byte) (any, error) { return x509.ParseECPrivateKey(der) },
	}
	for _, parse := range parsers {
		key, err := parse(keyDER)
		if err != nil {
			continue
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("private key type %T does not implement crypto.Signer", key)
		}
		return signer, nil
	}
	return nil, errors.New("unsupported or malformed private key")
}
