package xades

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/require"
	"github.com/viant/scy/auth/signing"
)

func TestSafeAlgorithmSuites(t *testing.T) {
	identity := newTestIdentity(t, 20)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	suites := []AlgorithmSuite{
		SuiteSHA256Exclusive,
		SuiteSHA384Exclusive,
		SuiteSHA512Exclusive,
		SuitePSSSHA256Exclusive,
		SuitePSSSHA384Exclusive,
		SuitePSSSHA512Exclusive,
		SuiteSHA256C14N11,
	}
	for _, suite := range suites {
		t.Run(suite.Name(), func(t *testing.T) {
			signed, err := SignEnveloped([]byte(`<Document><Value>42</Value></Document>`), identity, &Options{SigningTime: signingTime, Suite: suite})
			require.NoError(t, err)
			result, err := VerifyWithOptions(context.Background(), signed, &ValidationOptions{
				ExpectedCertificate: identity.Certificate,
				Time:                signingTime,
				AllowedSuites:       []AlgorithmSuite{suite},
			})
			require.NoError(t, err)
			require.Equal(t, suite.rsaMethod, result.SignatureMethod)
		})
	}
}

func TestSafeSuiteRejectsUnknownCanonicalization(t *testing.T) {
	_, err := SafeSuite(crypto.SHA256, "https://example.test/transform", false)
	require.ErrorContains(t, err, "unsupported canonicalization")

	identity := newTestIdentity(t, 27)
	at := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	signed, err := SignEnveloped([]byte(`<Document/>`), identity, &Options{SigningTime: at})
	require.NoError(t, err)
	unsafe := []byte(strings.Replace(string(signed), ExclusiveCanonicalization, "https://example.test/unsafe-transform", 1))
	_, err = Verify(unsafe, identity.Certificate, at)
	require.ErrorContains(t, err, "not allowed")
}

func TestXMLResourceLimits(t *testing.T) {
	identity := newTestIdentity(t, 28)
	at := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	_, err := SignEnveloped([]byte(`<Document><Value>too large</Value></Document>`), identity, &Options{
		SigningTime:      at,
		MaxDocumentBytes: 8,
	})
	require.ErrorContains(t, err, "maximum size")

	signed, err := SignEnveloped([]byte(`<A><B><C/></B></A>`), identity, &Options{SigningTime: at})
	require.NoError(t, err)
	_, err = VerifyWithOptions(context.Background(), signed, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                at,
		MaxXMLDepth:         2,
	})
	require.ErrorContains(t, err, "maximum XML depth")
}

func TestPackagingModes(t *testing.T) {
	identity := newTestIdentity(t, 21)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	document := []byte(`<Document><Value>packaging</Value></Document>`)

	enveloping, err := SignEnveloping(document, identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)
	result, err := Verify(enveloping, identity.Certificate, signingTime)
	require.NoError(t, err)
	require.Equal(t, PackagingEnveloping, result.Packaging)
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(enveloping))
	signature := doc.Root()
	dataReference := directChildren(directChildren(signature, DSNamespace, "SignedInfo")[0], DSNamespace, "Reference")[0]
	dataID := strings.TrimPrefix(dataReference.SelectAttrValue("URI", ""), "#")
	duplicate := element("ds", "Object")
	duplicate.CreateAttr("Id", dataID)
	signature.AddChild(duplicate)
	wrapped, err := doc.WriteToBytes()
	require.NoError(t, err)
	_, err = Verify(wrapped, identity.Certificate, signingTime)
	require.ErrorContains(t, err, "exactly one referenced ds:Object")

	const uri = "urn:document:invoice-1"
	detached, err := SignDetached(document, uri, identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)
	_, err = Verify(detached, identity.Certificate, signingTime)
	require.ErrorContains(t, err, "explicit Resolver")
	called := false
	result, err = VerifyWithOptions(context.Background(), detached, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                signingTime,
		Resolver: ResolverFunc(func(_ context.Context, actualURI string) ([]byte, error) {
			called = true
			require.Equal(t, uri, actualURI)
			return document, nil
		}),
	})
	require.NoError(t, err)
	require.True(t, called)
	require.Equal(t, PackagingDetached, result.Packaging)
	require.Equal(t, uri, result.ReferenceURI)

	_, err = VerifyWithOptions(context.Background(), detached, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                signingTime,
		Resolver: ResolverFunc(func(context.Context, string) ([]byte, error) {
			return []byte(`<Document><Value>tampered</Value></Document>`), nil
		}),
	})
	require.ErrorContains(t, err, "digest mismatch")
}

func TestTrustPolicyAndRevocationHook(t *testing.T) {
	identity, root := newChainedIdentity(t)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	signed, err := SignEnveloped([]byte(`<Document/>`), identity, &Options{SigningTime: signingTime, IncludeChain: true})
	require.NoError(t, err)
	roots := x509.NewCertPool()
	roots.AddCert(root)
	checker := &recordingRevocationChecker{}
	result, err := VerifyWithOptions(context.Background(), signed, &ValidationOptions{
		Time: signingTime,
		Trust: &TrustPolicy{
			Roots:      roots,
			Revocation: checker,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, result.Trust)
	require.NotEmpty(t, result.Trust.Chains)
	require.Equal(t, 1, checker.calls)
	_, err = VerifyWithOptions(context.Background(), signed, &ValidationOptions{
		Time: signingTime,
		Trust: &TrustPolicy{
			Roots:      roots,
			Revocation: &recordingRevocationChecker{err: errors.New("certificate revoked")},
		},
	})
	require.ErrorContains(t, err, "certificate revoked")

	wrongRoots := x509.NewCertPool()
	wrongRoots.AddCert(newTestIdentity(t, 22).Certificate)
	_, err = VerifyWithOptions(context.Background(), signed, &ValidationOptions{
		Time:  signingTime,
		Trust: &TrustPolicy{Roots: wrongRoots},
	})
	require.ErrorContains(t, err, "unknown authority")
}

func TestSignatureTimestampLifecycle(t *testing.T) {
	identity := newTestIdentity(t, 23)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	signed, err := SignEnveloped([]byte(`<Document/>`), identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)
	provider := &timestampRecorder{token: []byte("test-rfc3161-token"), timestamp: signingTime.Add(time.Minute)}
	timestamped, err := AddSignatureTimestamp(context.Background(), signed, provider, crypto.SHA256)
	require.NoError(t, err)
	require.NotEmpty(t, provider.imprint)

	result, err := VerifyWithOptions(context.Background(), timestamped, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                signingTime,
		TimestampVerifier:   provider,
		RequireTimestamp:    true,
	})
	require.NoError(t, err)
	require.NotNil(t, result.TimestampTime)
	require.Equal(t, provider.timestamp, *result.TimestampTime)
	tamperedToken := []byte(strings.Replace(string(timestamped), base64.StdEncoding.EncodeToString(provider.token), base64.StdEncoding.EncodeToString([]byte("tampered-token")), 1))
	_, err = VerifyWithOptions(context.Background(), tamperedToken, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                signingTime,
		TimestampVerifier:   provider,
	})
	require.ErrorContains(t, err, "timestamp token binding mismatch")

	_, err = VerifyWithOptions(context.Background(), signed, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                signingTime,
		TimestampVerifier:   provider,
		RequireTimestamp:    true,
	})
	require.ErrorContains(t, err, "timestamp is required")
}

func TestSignaturePolicyLifecycle(t *testing.T) {
	identity := newTestIdentity(t, 24)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	policyDocument := []byte("policy version 1")
	policyDigest, err := digestBytes(crypto.SHA256, policyDocument)
	require.NoError(t, err)
	policy := &SignaturePolicy{
		Identifier:  "urn:policy:test:v1",
		Description: "Test signing policy",
		Digest:      policyDigest,
	}
	signed, err := SignEnveloped([]byte(`<Document/>`), identity, &Options{SigningTime: signingTime, SignaturePolicy: policy})
	require.NoError(t, err)
	result, err := VerifyWithOptions(context.Background(), signed, &ValidationOptions{
		ExpectedCertificate:    identity.Certificate,
		Time:                   signingTime,
		RequireSignaturePolicy: true,
		PolicyResolver: PolicyResolverFunc(func(_ context.Context, identifier string) ([]byte, error) {
			require.Equal(t, policy.Identifier, identifier)
			return policyDocument, nil
		}),
	})
	require.NoError(t, err)
	require.Equal(t, policy.Identifier, result.SignaturePolicy.Identifier)

	_, err = VerifyWithOptions(context.Background(), signed, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                signingTime,
		PolicyResolver: PolicyResolverFunc(func(context.Context, string) ([]byte, error) {
			return []byte("wrong policy"), nil
		}),
	})
	require.ErrorContains(t, err, "policy digest mismatch")
}

func TestLongTermEvidenceLifecycle(t *testing.T) {
	identity := newTestIdentity(t, 25)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	signed, err := SignEnveloped([]byte(`<Document/>`), identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)
	timestamp := &timestampRecorder{token: []byte("timestamp-token"), timestamp: signingTime.Add(time.Minute)}
	timestamped, err := AddSignatureTimestamp(context.Background(), signed, timestamp, crypto.SHA256)
	require.NoError(t, err)
	evidence := &ValidationEvidence{
		Certificates:  []*x509.Certificate{identity.Certificate},
		OCSPResponses: [][]byte{[]byte("ocsp-response")},
		CRLs:          [][]byte{[]byte("crl")},
	}
	evidenceValidator := &recordingEvidenceValidator{}
	longTerm, err := AddLongTermValidationEvidence(context.Background(), timestamped, evidence, evidenceValidator, signingTime)
	require.NoError(t, err)
	require.Equal(t, 1, evidenceValidator.calls)

	result, err := VerifyWithOptions(context.Background(), longTerm, &ValidationOptions{
		ExpectedCertificate:     identity.Certificate,
		Time:                    signingTime,
		TimestampVerifier:       timestamp,
		RequireTimestamp:        true,
		EvidenceValidator:       evidenceValidator,
		RequireLongTermEvidence: true,
	})
	require.NoError(t, err)
	require.NotNil(t, result.LongTermEvidence)
	require.Len(t, result.LongTermEvidence.Certificates, 1)
	require.Equal(t, 2, evidenceValidator.calls)
}

func TestLegacySigningCertificateRequiresOptIn(t *testing.T) {
	identity := newTestIdentity(t, 26)
	signingTime := time.Date(2026, 8, 11, 10, 30, 0, 0, time.UTC)
	signed, err := SignEnveloped([]byte(`<Document/>`), identity, &Options{SigningTime: signingTime})
	require.NoError(t, err)
	legacy := makeLegacySigningCertificate(t, signed, identity, SuiteSHA256Exclusive)

	_, err = VerifyWithOptions(context.Background(), legacy, &ValidationOptions{
		ExpectedCertificate: identity.Certificate,
		Time:                signingTime,
	})
	require.ErrorContains(t, err, "SigningCertificateV2")
	_, err = VerifyWithOptions(context.Background(), legacy, &ValidationOptions{
		ExpectedCertificate:           identity.Certificate,
		Time:                          signingTime,
		AllowLegacySigningCertificate: true,
	})
	require.NoError(t, err)
}

type recordingRevocationChecker struct {
	calls int
	err   error
}

func (r *recordingRevocationChecker) Check(_ context.Context, _, _ *x509.Certificate, _ time.Time) error {
	r.calls++
	return r.err
}

type timestampRecorder struct {
	token     []byte
	imprint   []byte
	hash      crypto.Hash
	timestamp time.Time
}

type recordingEvidenceValidator struct{ calls int }

func (r *recordingEvidenceValidator) ValidateEvidence(_ context.Context, evidence *ValidationEvidence, chain []*x509.Certificate, _ time.Time) error {
	r.calls++
	if len(chain) == 0 || evidence == nil {
		return errors.New("missing validation input")
	}
	return nil
}

func (r *timestampRecorder) Timestamp(_ context.Context, imprint []byte, hash crypto.Hash) ([]byte, error) {
	r.imprint = append([]byte(nil), imprint...)
	r.hash = hash
	return append([]byte(nil), r.token...), nil
}

func (r *timestampRecorder) VerifyTimestamp(_ context.Context, token, imprint []byte, hash crypto.Hash, _ time.Time) (time.Time, error) {
	if !bytes.Equal(token, r.token) || !bytes.Equal(imprint, r.imprint) || hash != r.hash {
		return time.Time{}, errors.New("timestamp token binding mismatch")
	}
	return r.timestamp, nil
}

func newChainedIdentity(t *testing.T) (*signing.Identity, *x509.Certificate) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(100),
		Subject:               pkix.Name{CommonName: "Scy Test Root"},
		NotBefore:             time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	leafTemplate := testCertificateTemplate(101)
	leafTemplate.Issuer = root.Subject
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)
	identity, err := signing.NewIdentity(leafKey, leaf, root)
	require.NoError(t, err)
	return identity, root
}

func makeLegacySigningCertificate(t *testing.T, signed []byte, identity *signing.Identity, suite AlgorithmSuite) []byte {
	t.Helper()
	doc := etree.NewDocument()
	require.NoError(t, doc.ReadFromBytes(signed))
	signature := elementsByNamespace(doc.Root(), DSNamespace, "Signature")[0]
	properties := elementsByNamespace(signature, XAdESNamespace, "SignedProperties")[0]
	signingCertificate := elementsByNamespace(properties, XAdESNamespace, "SigningCertificateV2")[0]
	signingCertificate.Tag = "SigningCertificate"
	cert := directChildren(signingCertificate, XAdESNamespace, "Cert")[0]
	issuerSerial := element("xades", "IssuerSerial")
	cert.AddChild(issuerSerial)
	child(issuerSerial, "ds", "X509IssuerName", identity.Certificate.Issuer.String())
	child(issuerSerial, "ds", "X509SerialNumber", identity.Certificate.SerialNumber.String())
	canonicalizer, err := suite.canonicalizer()
	require.NoError(t, err)
	propertiesDigest, err := digestElement(canonicalizer, suite.hash, properties)
	require.NoError(t, err)
	signedInfo := directChildren(signature, DSNamespace, "SignedInfo")[0]
	for _, reference := range directChildren(signedInfo, DSNamespace, "Reference") {
		if reference.SelectAttrValue("Type", "") == SignedPropertiesType {
			digestValue := directChildren(reference, DSNamespace, "DigestValue")[0]
			digestValue.SetText(base64.StdEncoding.EncodeToString(propertiesDigest))
		}
	}
	canonicalSignedInfo, err := canonicalizer.Canonicalize(signedInfo.Copy())
	require.NoError(t, err)
	digest, err := digestBytes(suite.hash, canonicalSignedInfo)
	require.NoError(t, err)
	rawSignature, err := identity.Signer.Sign(rand.Reader, digest, signerOptions(suite))
	require.NoError(t, err)
	directChildren(signature, DSNamespace, "SignatureValue")[0].SetText(base64.StdEncoding.EncodeToString(rawSignature))
	result, err := doc.WriteToBytes()
	require.NoError(t, err)
	return result
}
