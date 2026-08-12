package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNewIdentityPEM(t *testing.T) {
	privateKey, certificate := testKeyPair(t, 10)
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	combinedPEM := append(append([]byte(nil), certificatePEM...), keyPEM...)
	identity, err := NewIdentityPEM(certificatePEM, combinedPEM, "")
	require.NoError(t, err)
	require.True(t, identity.Certificate.Equal(certificate))
	require.Len(t, identity.CertificateChainDER(), 1)
}

func TestNewIdentityRejectsMismatchedKey(t *testing.T) {
	_, certificate := testKeyPair(t, 11)
	otherKey, _ := testKeyPair(t, 12)

	_, err := NewIdentity(otherKey, certificate)
	require.ErrorContains(t, err, "does not match")
}

func testKeyPair(t *testing.T, serial int64) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Scy Identity Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return privateKey, certificate
}
