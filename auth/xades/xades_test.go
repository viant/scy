package xades

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/stretchr/testify/require"
	"github.com/viant/scy/auth/signing"
)

func TestSignEnvelopedAndVerify(t *testing.T) {
	identity := newTestIdentity(t, 1)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	document := []byte(`<AuthTokenRequest xmlns="urn:test"><Challenge>abc-123</Challenge><ContextIdentifier><Nip>1234567890</Nip></ContextIdentifier></AuthTokenRequest>`)

	signed, err := SignEnveloped(document, identity, &Options{
		SigningTime:        signingTime,
		SignatureID:        "Signature-test",
		SignedPropertiesID: "SignedProperties-test",
	})
	require.NoError(t, err)
	require.Contains(t, string(signed), `Type="http://uri.etsi.org/01903#SignedProperties"`)
	require.Contains(t, string(signed), `<xades:SigningCertificateV2>`)
	require.NotContains(t, string(signed), `<xades:SigningCertificate>`)
	require.Contains(t, string(signed), `<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"`)

	result, err := Verify(signed, identity.Certificate, signingTime)
	require.NoError(t, err)
	require.True(t, result.Certificate.Equal(identity.Certificate))
	require.Equal(t, signingTime, result.SigningTime)
	require.Equal(t, "Signature-test", result.SignatureID)

	// Cross-check the XMLDSig core with an independent validator. Scy's Verify
	// additionally validates the XAdES SignedProperties reference.
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))
	validator := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{identity.Certificate}})
	_, err = validator.Validate(doc.Root())
	require.NoError(t, err)
}

func TestVerifyRejectsTampering(t *testing.T) {
	identity := newTestIdentity(t, 2)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	document := []byte(`<Request><Challenge>original</Challenge></Request>`)
	signed, err := SignEnveloped(document, identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)

	tamperedDocument := []byte(strings.Replace(string(signed), "original", "altered", 1))
	_, err = Verify(tamperedDocument, identity.Certificate, signingTime)
	require.ErrorContains(t, err, "digest mismatch")

	tamperedProperties := []byte(strings.Replace(string(signed), "2026-08-11T10:30:00Z", "2026-08-11T10:31:00Z", 1))
	_, err = Verify(tamperedProperties, identity.Certificate, signingTime)
	require.ErrorContains(t, err, "digest mismatch")
}

func TestVerifyRejectsUnexpectedCertificate(t *testing.T) {
	identity := newTestIdentity(t, 3)
	other := newTestIdentity(t, 4)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	signed, err := SignEnveloped([]byte(`<Request/>`), identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)

	_, err = Verify(signed, other.Certificate, signingTime)
	require.ErrorContains(t, err, "does not match expected certificate")
}

func TestSignEnvelopedECDSA(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := testCertificateTemplate(5)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	identity, err := signing.NewIdentity(privateKey, certificate)
	require.NoError(t, err)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)

	signed, err := SignEnveloped([]byte(`<Request><Challenge>ec</Challenge></Request>`), identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)
	require.Contains(t, string(signed), SignatureMethodECDSA256)
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))
	signatureValue := elementsByNamespace(doc.Root(), DSNamespace, "SignatureValue")[0]
	rawSignature, err := decodeBase64Text(signatureValue, "SignatureValue")
	require.NoError(t, err)
	require.Len(t, rawSignature, 64, "P-256 XMLDSig signatures must use fixed-width R || S")
	result, err := Verify(signed, certificate, signingTime)
	require.NoError(t, err)
	require.Equal(t, SignatureMethodECDSA256, result.SignatureMethod)
}

func newTestIdentity(t testing.TB, serial int64) *signing.Identity {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := testCertificateTemplate(serial)
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	identity, err := signing.NewIdentity(privateKey, certificate)
	require.NoError(t, err)
	return identity
}

func testCertificateTemplate(serial int64) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: "Scy XAdES Test"},
		Issuer:       pkix.Name{CommonName: "Scy XAdES Test"},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
}
