package gcp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/viant/afs"
)

const (
	CertURL = "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com"
)

func RSAPublicKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	return RSAPublicKeyWithURL(ctx, CertURL, keyID)
}

func RSAPublicKeyWithURL(ctx context.Context, URL, key string) (*rsa.PublicKey, error) {
	fs := afs.New()
	certData, err := fs.DownloadWithURL(ctx, URL)
	if err != nil {
		return nil, err
	}
	certMap := map[string]string{}
	if err = json.Unmarshal(certData, &certMap); err != nil {
		return nil, err
	}
	rootPEM, ok := certMap[key]
	if ok || len(certMap) == 0 {
		return decodePEM(rootPEM)
	}
	return nil, err
}

func decodePEM(rootPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(rootPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaPublicKey, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected : %T, but had: %T", rsaPublicKey, cert.PublicKey)
	}
	return rsaPublicKey, nil
}
