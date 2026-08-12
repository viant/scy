// Package xades provides protocol-neutral XAdES signing and verification.
//
// The package deliberately accepts only whitelisted SHA-2, RSA, RSA-PSS,
// ECDSA, and canonicalization suites. It supports structured enveloped,
// enveloping, and explicitly resolved detached signatures, and contains no
// protocol-specific transport or token behavior.
package xades

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"github.com/viant/scy/auth/signing"
)

const (
	DSNamespace              = "http://www.w3.org/2000/09/xmldsig#"
	XAdESNamespace           = "http://uri.etsi.org/01903/v1.3.2#"
	CanonicalizationMethod   = ExclusiveCanonicalization
	EnvelopedSignatureMethod = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	DigestMethodSHA256       = "http://www.w3.org/2001/04/xmlenc#sha256"
	SignatureMethodRSA256    = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	SignatureMethodECDSA256  = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	SignedPropertiesType     = "http://uri.etsi.org/01903#SignedProperties"
)

type Packaging string

const (
	PackagingEnveloped  Packaging = "enveloped"
	PackagingEnveloping Packaging = "enveloping"
	PackagingDetached   Packaging = "detached"
)

// Options controls deterministic metadata in an XAdES signature. Empty IDs
// are generated with crypto/rand and an empty SigningTime uses time.Now().
type Options struct {
	SigningTime        time.Time
	SignatureID        string
	SignedPropertiesID string
	IncludeChain       bool
	Suite              AlgorithmSuite
	Packaging          Packaging
	ReferenceURI       string
	SignaturePolicy    *SignaturePolicy
	MaxDocumentBytes   int
	MaxXMLDepth        int
}

// Result is the verified identity and XAdES metadata.
type Result struct {
	Certificate      *x509.Certificate
	SigningTime      time.Time
	SignatureID      string
	SignatureMethod  string
	Trust            *TrustResult
	Packaging        Packaging
	ReferenceURI     string
	TimestampTime    *time.Time
	SignaturePolicy  *SignaturePolicy
	LongTermEvidence *ValidationEvidence
}

// SignEnveloped adds an enveloped XAdES signature using a whitelisted suite.
func SignEnveloped(document []byte, identity *signing.Identity, options *Options) ([]byte, error) {
	cloned := cloneOptions(options)
	cloned.Packaging = PackagingEnveloped
	return sign(document, identity, cloned)
}

// SignEnveloping creates a Signature document that contains the signed XML in
// a ds:Object. This mode never resolves external resources.
func SignEnveloping(document []byte, identity *signing.Identity, options *Options) ([]byte, error) {
	cloned := cloneOptions(options)
	cloned.Packaging = PackagingEnveloping
	return sign(document, identity, cloned)
}

// SignDetached creates a detached signature over an XML document. referenceURI
// is metadata only during generation; SignDetached performs no network access.
func SignDetached(document []byte, referenceURI string, identity *signing.Identity, options *Options) ([]byte, error) {
	if strings.TrimSpace(referenceURI) == "" || strings.HasPrefix(referenceURI, "#") {
		return nil, errors.New("detached signature requires a non-fragment reference URI")
	}
	cloned := cloneOptions(options)
	cloned.Packaging = PackagingDetached
	cloned.ReferenceURI = referenceURI
	return sign(document, identity, cloned)
}

func cloneOptions(options *Options) *Options {
	if options == nil {
		return &Options{}
	}
	result := *options
	return &result
}

func sign(document []byte, identity *signing.Identity, options *Options) ([]byte, error) {
	if options == nil {
		options = &Options{}
	}
	if options.Packaging == "" {
		options.Packaging = PackagingEnveloped
	}
	signingTime := options.SigningTime
	if signingTime.IsZero() {
		signingTime = time.Now()
	}
	signingTime = signingTime.UTC()
	if err := identity.Validate(signingTime); err != nil {
		return nil, err
	}
	suite := options.Suite
	if suite.name == "" {
		suite = SuiteSHA256Exclusive
	}
	if err := suite.validate(); err != nil {
		return nil, err
	}
	signatureMethod, err := signatureMethodFor(identity.Signer.Public(), suite)
	if err != nil {
		return nil, err
	}

	doc, err := parseXML(document, options.MaxDocumentBytes, options.MaxXMLDepth, "XML document")
	if err != nil {
		return nil, err
	}
	root := doc.Root()
	if options.Packaging == PackagingEnveloped && len(elementsByNamespace(root, DSNamespace, "Signature")) != 0 {
		return nil, errors.New("XML document already contains a Signature")
	}

	signatureID, err := idOrRandom(options.SignatureID, "Signature-")
	if err != nil {
		return nil, err
	}
	propertiesID, err := idOrRandom(options.SignedPropertiesID, "SignedProperties-")
	if err != nil {
		return nil, err
	}

	signature := element("ds", "Signature")
	signature.CreateAttr("xmlns:ds", DSNamespace)
	signature.CreateAttr("Id", signatureID)
	resultDoc := doc
	dataElement := root
	referenceURI := ""
	documentTransforms := []string{EnvelopedSignatureMethod, suite.canonicalization}
	var dataObject *etree.Element
	switch options.Packaging {
	case PackagingEnveloped:
	case PackagingEnveloping:
		dataID, err := idOrRandom("", "Object-")
		if err != nil {
			return nil, err
		}
		dataObject = element("ds", "Object")
		dataObject.CreateAttr("xmlns:ds", DSNamespace)
		dataObject.CreateAttr("Id", dataID)
		dataObject.AddChild(root.Copy())
		dataElement = dataObject
		referenceURI = "#" + dataID
		documentTransforms = []string{suite.canonicalization}
		resultDoc = etree.NewDocument()
		resultDoc.SetRoot(signature)
	case PackagingDetached:
		if strings.TrimSpace(options.ReferenceURI) == "" || strings.HasPrefix(options.ReferenceURI, "#") {
			return nil, errors.New("detached signature requires a non-fragment reference URI")
		}
		referenceURI = options.ReferenceURI
		documentTransforms = []string{suite.canonicalization}
		resultDoc = etree.NewDocument()
		resultDoc.SetRoot(signature)
	default:
		return nil, fmt.Errorf("unsupported XAdES packaging %q", options.Packaging)
	}

	canonicalizer, err := suite.canonicalizer()
	if err != nil {
		return nil, err
	}
	documentDigest, err := digestElement(canonicalizer, suite.hash, dataElement)
	if err != nil {
		return nil, fmt.Errorf("digest XML document: %w", err)
	}
	if options.Packaging == PackagingEnveloped {
		root.AddChild(signature)
	}

	signedInfo := element("ds", "SignedInfo")
	signedInfo.CreateAttr("xmlns:ds", DSNamespace)
	signature.AddChild(signedInfo)
	method(signedInfo, "CanonicalizationMethod", suite.canonicalization)
	method(signedInfo, "SignatureMethod", signatureMethod)
	documentReference := reference(signedInfo, referenceURI, "", suite.digestMethod, documentDigest)
	transforms := element("ds", "Transforms")
	documentReference.InsertChildAt(0, transforms)
	for _, transform := range documentTransforms {
		method(transforms, "Transform", transform)
	}

	keyInfo := element("ds", "KeyInfo")
	x509Data := element("ds", "X509Data")
	keyInfo.AddChild(x509Data)
	certificates := identity.CertificateChainDER()
	if !options.IncludeChain && len(certificates) > 1 {
		certificates = certificates[:1]
	}
	for _, certificate := range certificates {
		child(x509Data, "ds", "X509Certificate", base64.StdEncoding.EncodeToString(certificate))
	}

	object := element("ds", "Object")
	qualifying := element("xades", "QualifyingProperties")
	qualifying.CreateAttr("xmlns:xades", XAdESNamespace)
	qualifying.CreateAttr("Target", "#"+signatureID)
	object.AddChild(qualifying)
	signedProperties := element("xades", "SignedProperties")
	signedProperties.CreateAttr("xmlns:xades", XAdESNamespace)
	signedProperties.CreateAttr("xmlns:ds", DSNamespace)
	signedProperties.CreateAttr("Id", propertiesID)
	qualifying.AddChild(signedProperties)
	signedSignatureProperties := element("xades", "SignedSignatureProperties")
	signedProperties.AddChild(signedSignatureProperties)
	child(signedSignatureProperties, "xades", "SigningTime", signingTime.Format(time.RFC3339))
	addSigningCertificateV2(signedSignatureProperties, identity.Certificate, suite)
	if err := addSignaturePolicy(signedSignatureProperties, options.SignaturePolicy, suite); err != nil {
		return nil, err
	}

	signature.AddChild(keyInfo)
	if dataObject != nil {
		signature.AddChild(dataObject)
	}
	signature.AddChild(object)
	propertiesDigest, err := digestElement(canonicalizer, suite.hash, signedProperties)
	if err != nil {
		return nil, fmt.Errorf("digest XAdES SignedProperties: %w", err)
	}
	propertiesReference := reference(signedInfo, "#"+propertiesID, SignedPropertiesType, suite.digestMethod, propertiesDigest)
	propertyTransforms := element("ds", "Transforms")
	propertiesReference.InsertChildAt(0, propertyTransforms)
	method(propertyTransforms, "Transform", suite.canonicalization)

	canonicalSignedInfo, err := canonicalizer.Canonicalize(signedInfo.Copy())
	if err != nil {
		return nil, fmt.Errorf("canonicalize SignedInfo: %w", err)
	}
	digest, err := digestBytes(suite.hash, canonicalSignedInfo)
	if err != nil {
		return nil, err
	}
	rawSignature, err := identity.Signer.Sign(rand.Reader, digest, signerOptions(suite))
	if err != nil {
		return nil, fmt.Errorf("sign SignedInfo: %w", err)
	}
	if publicKey, ok := identity.Signer.Public().(*ecdsa.PublicKey); ok {
		rawSignature, err = encodeECDSASignature(rawSignature, publicKey)
		if err != nil {
			return nil, err
		}
	}
	signatureValue := element("ds", "SignatureValue")
	signatureValue.SetText(base64.StdEncoding.EncodeToString(rawSignature))
	signature.InsertChildAt(1, signatureValue)

	result, err := resultDoc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize signed XML: %w", err)
	}
	return result, nil
}

// ValidationOptions controls signature verification. Network access is never
// implicit: trust and revocation behavior must be supplied explicitly.
type ValidationOptions struct {
	ExpectedCertificate           *x509.Certificate
	Time                          time.Time
	Trust                         *TrustPolicy
	AllowedSuites                 []AlgorithmSuite
	AllowLegacySigningCertificate bool
	Resolver                      Resolver
	TimestampVerifier             TimestampVerifier
	RequireTimestamp              bool
	PolicyResolver                PolicyResolver
	RequireSignaturePolicy        bool
	EvidenceValidator             EvidenceValidator
	RequireLongTermEvidence       bool
	MaxDocumentBytes              int
	MaxXMLDepth                   int
}

// Resolver supplies detached content. Scy never dereferences signature URIs
// itself; applications retain full control over filesystem and network access.
type Resolver interface {
	Resolve(ctx context.Context, uri string) ([]byte, error)
}

type ResolverFunc func(ctx context.Context, uri string) ([]byte, error)

func (f ResolverFunc) Resolve(ctx context.Context, uri string) ([]byte, error) { return f(ctx, uri) }

// Verify verifies a modern signature without certificate-path trust. Use
// VerifyWithOptions to require trust, restrict algorithms, or allow legacy
// SigningCertificate properties.
func Verify(document []byte, expectedCertificate *x509.Certificate, at time.Time) (*Result, error) {
	return VerifyWithOptions(context.Background(), document, &ValidationOptions{
		ExpectedCertificate: expectedCertificate,
		Time:                at,
	})
}

// VerifyWithOptions verifies XMLDSig integrity, XAdES qualifying properties,
// optional certificate pinning, and optional certificate-path trust.
func VerifyWithOptions(ctx context.Context, document []byte, options *ValidationOptions) (*Result, error) {
	if options == nil {
		options = &ValidationOptions{}
	}
	doc, err := parseXML(document, options.MaxDocumentBytes, options.MaxXMLDepth, "XML document")
	if err != nil {
		return nil, err
	}
	root := doc.Root()
	signatures := elementsByNamespace(root, DSNamespace, "Signature")
	if len(signatures) != 1 {
		return nil, fmt.Errorf("expected exactly one XML Signature, got %d", len(signatures))
	}
	signature := signatures[0]
	isSignatureRoot := signature == root
	if !isSignatureRoot && signature.Parent() != root {
		return nil, errors.New("Signature must be a direct child of the document root")
	}
	signatureID := signature.SelectAttrValue("Id", "")
	if signatureID == "" {
		return nil, errors.New("Signature has no Id")
	}

	signedInfo, err := exactlyOneChild(signature, DSNamespace, "SignedInfo")
	if err != nil {
		return nil, err
	}
	signatureValue, err := exactlyOneChild(signature, DSNamespace, "SignatureValue")
	if err != nil {
		return nil, err
	}
	canonicalizationElement, err := exactlyOneChild(signedInfo, DSNamespace, "CanonicalizationMethod")
	if err != nil {
		return nil, err
	}
	canonicalizationMethod := canonicalizationElement.SelectAttrValue("Algorithm", "")
	signatureMethodElement, err := exactlyOneChild(signedInfo, DSNamespace, "SignatureMethod")
	if err != nil {
		return nil, err
	}
	signatureMethod := signatureMethodElement.SelectAttrValue("Algorithm", "")
	references := directChildren(signedInfo, DSNamespace, "Reference")
	if len(references) != 2 {
		return nil, fmt.Errorf("expected exactly two signed references, got %d", len(references))
	}
	digestMethodElement, err := exactlyOneChild(references[0], DSNamespace, "DigestMethod")
	if err != nil {
		return nil, err
	}
	allowedSuites := options.AllowedSuites
	if len(allowedSuites) == 0 {
		allowedSuites = StandardSuites()
	}
	suite, err := selectSuite(allowedSuites, canonicalizationMethod, digestMethodElement.SelectAttrValue("Algorithm", ""), signatureMethod)
	if err != nil {
		return nil, err
	}

	certificates, err := embeddedCertificates(signature)
	if err != nil {
		return nil, err
	}
	certificate := certificates[0]
	if options.ExpectedCertificate != nil && !certificate.Equal(options.ExpectedCertificate) {
		return nil, errors.New("embedded signing certificate does not match expected certificate")
	}
	at := options.Time
	if at.IsZero() {
		at = time.Now()
	}
	if at.Before(certificate.NotBefore) || at.After(certificate.NotAfter) {
		return nil, fmt.Errorf("signing certificate is not valid at %s", at.UTC().Format(time.RFC3339))
	}
	canonicalizer, err := suite.canonicalizer()
	if err != nil {
		return nil, err
	}
	canonicalSignedInfo, err := canonicalizer.Canonicalize(signedInfo.Copy())
	if err != nil {
		return nil, fmt.Errorf("canonicalize SignedInfo: %w", err)
	}
	rawSignature, err := decodeBase64Text(signatureValue, "SignatureValue")
	if err != nil {
		return nil, err
	}
	digest, err := digestBytes(suite.hash, canonicalSignedInfo)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(certificate.PublicKey, suite, signatureMethod, digest, rawSignature); err != nil {
		return nil, err
	}
	var documentReference, propertiesReference *etree.Element
	for _, ref := range references {
		switch {
		case ref.SelectAttrValue("Type", "") == "":
			if documentReference != nil {
				return nil, errors.New("SignedInfo contains multiple data references")
			}
			documentReference = ref
		case strings.HasPrefix(ref.SelectAttrValue("URI", ""), "#") && ref.SelectAttrValue("Type", "") == SignedPropertiesType:
			propertiesReference = ref
		default:
			return nil, errors.New("SignedInfo contains an unsupported reference")
		}
	}
	if documentReference == nil || propertiesReference == nil {
		return nil, errors.New("SignedInfo is missing the document or SignedProperties reference")
	}
	if err := verifyReferenceAlgorithms(propertiesReference, false, suite); err != nil {
		return nil, err
	}

	packaging, dataElement, referenceURI, err := resolveSignedData(ctx, root, signature, documentReference, options.Resolver, options.MaxDocumentBytes, options.MaxXMLDepth)
	if err != nil {
		return nil, err
	}
	if err := verifyReferenceAlgorithms(documentReference, packaging == PackagingEnveloped, suite); err != nil {
		return nil, err
	}
	if err := verifyDigest(canonicalizer, suite.hash, dataElement, documentReference); err != nil {
		return nil, fmt.Errorf("verify document reference: %w", err)
	}

	propertiesID := strings.TrimPrefix(propertiesReference.SelectAttrValue("URI", ""), "#")
	properties := elementsWithID(signature, XAdESNamespace, "SignedProperties", propertiesID)
	if len(properties) != 1 {
		return nil, fmt.Errorf("expected exactly one referenced SignedProperties, got %d", len(properties))
	}
	if err := verifyDigest(canonicalizer, suite.hash, properties[0], propertiesReference); err != nil {
		return nil, fmt.Errorf("verify SignedProperties reference: %w", err)
	}
	qualifying := properties[0].Parent()
	if qualifying == nil || qualifying.NamespaceURI() != XAdESNamespace || qualifying.Tag != "QualifyingProperties" || qualifying.SelectAttrValue("Target", "") != "#"+signatureID {
		return nil, errors.New("QualifyingProperties does not target the XML Signature")
	}
	signingTime, err := verifyQualifyingProperties(properties[0], certificate, suite, options.AllowLegacySigningCertificate)
	if err != nil {
		return nil, err
	}
	signedSignatureProperties, err := exactlyOneChild(properties[0], XAdESNamespace, "SignedSignatureProperties")
	if err != nil {
		return nil, err
	}
	signaturePolicy, err := verifySignaturePolicy(ctx, signedSignatureProperties, suite, options.PolicyResolver, options.RequireSignaturePolicy)
	if err != nil {
		return nil, err
	}
	var trustResult *TrustResult
	if options.Trust != nil {
		trustResult, err = options.Trust.Verify(ctx, certificate, certificates[1:], at)
		if err != nil {
			return nil, err
		}
	}
	timestampTime, err := verifySignatureTimestamp(ctx, signature, options.TimestampVerifier, suite.hash, at, options.RequireTimestamp)
	if err != nil {
		return nil, err
	}
	longTermEvidence, err := verifyLongTermEvidence(ctx, signature, certificates, options.EvidenceValidator, at, options.RequireLongTermEvidence)
	if err != nil {
		return nil, err
	}
	if longTermEvidence != nil && timestampTime == nil {
		return nil, errors.New("long-term validation evidence requires a verified signature timestamp")
	}
	return &Result{Certificate: certificate, SigningTime: signingTime, SignatureID: signatureID, SignatureMethod: signatureMethod, Trust: trustResult, Packaging: packaging, ReferenceURI: referenceURI, TimestampTime: timestampTime, SignaturePolicy: signaturePolicy, LongTermEvidence: longTermEvidence}, nil
}

func resolveSignedData(ctx context.Context, root, signature, reference *etree.Element, resolver Resolver, maxBytes, maxDepth int) (Packaging, *etree.Element, string, error) {
	uri := reference.SelectAttrValue("URI", "")
	if signature != root {
		if uri != "" {
			return "", nil, "", errors.New("enveloped signature data reference must have an empty URI")
		}
		unsignedRoot := root.Copy()
		signatures := elementsByNamespace(unsignedRoot, DSNamespace, "Signature")
		if len(signatures) != 1 || signatures[0].Parent() != unsignedRoot {
			return "", nil, "", errors.New("could not isolate enveloped Signature")
		}
		unsignedRoot.RemoveChild(signatures[0])
		return PackagingEnveloped, unsignedRoot, "", nil
	}
	if strings.HasPrefix(uri, "#") {
		id := strings.TrimPrefix(uri, "#")
		if id == "" {
			return "", nil, "", errors.New("enveloping reference has an empty fragment")
		}
		matches := elementsWithAnyID(signature, id)
		if len(matches) != 1 || matches[0].NamespaceURI() != DSNamespace || matches[0].Tag != "Object" {
			return "", nil, "", fmt.Errorf("expected exactly one referenced ds:Object, got %d", len(matches))
		}
		return PackagingEnveloping, matches[0], uri, nil
	}
	if uri == "" {
		return "", nil, "", errors.New("signature-root data reference must identify an object or detached resource")
	}
	if resolver == nil {
		return "", nil, "", errors.New("detached signature requires an explicit Resolver")
	}
	data, err := resolver.Resolve(ctx, uri)
	if err != nil {
		return "", nil, "", fmt.Errorf("resolve detached signature URI %q: %w", uri, err)
	}
	doc, err := parseXML(data, maxBytes, maxDepth, "detached XML content")
	if err != nil {
		return "", nil, "", err
	}
	return PackagingDetached, doc.Root(), uri, nil
}

func signatureMethodFor(publicKey crypto.PublicKey, suite AlgorithmSuite) (string, error) {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return "", fmt.Errorf("RSA signing key must be at least 2048 bits, got %d", key.N.BitLen())
		}
		return suite.rsaMethod, nil
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params().BitSize < 256 {
			return "", errors.New("ECDSA signing curve must be at least 256 bits")
		}
		return suite.ecdsaMethod, nil
	default:
		return "", fmt.Errorf("XAdES signer has unsupported public key type %T", publicKey)
	}
}

func encodeECDSASignature(der []byte, publicKey *ecdsa.PublicKey) ([]byte, error) {
	parsed := struct{ R, S *big.Int }{}
	rest, err := asn1.Unmarshal(der, &parsed)
	if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
		return nil, errors.New("ECDSA signer returned a malformed ASN.1 signature")
	}
	width := (publicKey.Curve.Params().BitSize + 7) / 8
	if parsed.R.Sign() <= 0 || parsed.S.Sign() <= 0 || len(parsed.R.Bytes()) > width || len(parsed.S.Bytes()) > width {
		return nil, errors.New("ECDSA signer returned an out-of-range signature")
	}
	result := make([]byte, width*2)
	parsed.R.FillBytes(result[:width])
	parsed.S.FillBytes(result[width:])
	return result, nil
}

func signerOptions(suite AlgorithmSuite) crypto.SignerOpts {
	if suite.rsaPSS {
		return &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: suite.hash}
	}
	return suite.hash
}

func verifySignature(publicKey crypto.PublicKey, suite AlgorithmSuite, method string, digest, signature []byte) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if method != suite.rsaMethod {
			return errors.New("SignatureMethod is incompatible with embedded RSA certificate")
		}
		if key.N.BitLen() < 2048 {
			return errors.New("embedded RSA certificate key is shorter than 2048 bits")
		}
		var err error
		if suite.rsaPSS {
			err = rsa.VerifyPSS(key, suite.hash, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: suite.hash})
		} else {
			err = rsa.VerifyPKCS1v15(key, suite.hash, digest, signature)
		}
		if err != nil {
			return fmt.Errorf("verify XML signature: %w", err)
		}
		return nil
	case *ecdsa.PublicKey:
		if method != suite.ecdsaMethod {
			return errors.New("SignatureMethod is incompatible with embedded ECDSA certificate")
		}
		width := (key.Curve.Params().BitSize + 7) / 8
		if width < 32 || len(signature) != width*2 {
			return errors.New("ECDSA SignatureValue is not fixed-width R || S")
		}
		r := new(big.Int).SetBytes(signature[:width])
		s := new(big.Int).SetBytes(signature[width:])
		if !ecdsa.Verify(key, digest, r, s) {
			return errors.New("verify XML ECDSA signature: invalid signature")
		}
		return nil
	default:
		return fmt.Errorf("embedded certificate has unsupported public key type %T", publicKey)
	}
}

func addSigningCertificateV2(parent *etree.Element, certificate *x509.Certificate, suite AlgorithmSuite) {
	signingCertificate := element("xades", "SigningCertificateV2")
	parent.AddChild(signingCertificate)
	cert := element("xades", "Cert")
	signingCertificate.AddChild(cert)
	certDigest := element("xades", "CertDigest")
	cert.AddChild(certDigest)
	method(certDigest, "DigestMethod", suite.digestMethod)
	digest, _ := digestBytes(suite.hash, certificate.Raw)
	child(certDigest, "ds", "DigestValue", base64.StdEncoding.EncodeToString(digest))
}

func reference(parent *etree.Element, uri, referenceType, digestMethod string, digest []byte) *etree.Element {
	result := element("ds", "Reference")
	result.CreateAttr("URI", uri)
	if referenceType != "" {
		result.CreateAttr("Type", referenceType)
	}
	parent.AddChild(result)
	method(result, "DigestMethod", digestMethod)
	child(result, "ds", "DigestValue", base64.StdEncoding.EncodeToString(digest))
	return result
}

func method(parent *etree.Element, name, algorithm string) *etree.Element {
	result := element("ds", name)
	result.CreateAttr("Algorithm", algorithm)
	parent.AddChild(result)
	return result
}

func child(parent *etree.Element, space, name, text string) *etree.Element {
	result := element(space, name)
	result.SetText(text)
	parent.AddChild(result)
	return result
}

func element(space, name string) *etree.Element { return &etree.Element{Space: space, Tag: name} }

func digestElement(canonicalizer dsig.Canonicalizer, hash crypto.Hash, element *etree.Element) ([]byte, error) {
	canonical, err := canonicalizer.Canonicalize(element.Copy())
	if err != nil {
		return nil, err
	}
	return digestBytes(hash, canonical)
}

func digestBytes(hash crypto.Hash, data []byte) ([]byte, error) {
	if !hash.Available() {
		return nil, fmt.Errorf("hash %s is unavailable", hash)
	}
	digest := hash.New()
	if _, err := digest.Write(data); err != nil {
		return nil, err
	}
	return digest.Sum(nil), nil
}

func idOrRandom(value, prefix string) (string, error) {
	if value != "" {
		return value, nil
	}
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate XML signature ID: %w", err)
	}
	return prefix + hex.EncodeToString(data), nil
}

func directChildren(parent *etree.Element, namespace, tag string) []*etree.Element {
	var result []*etree.Element
	for _, candidate := range parent.ChildElements() {
		if candidate.Tag == tag && candidate.NamespaceURI() == namespace {
			result = append(result, candidate)
		}
	}
	return result
}

func elementsByNamespace(root *etree.Element, namespace, tag string) []*etree.Element {
	var result []*etree.Element
	var walk func(*etree.Element)
	walk = func(element *etree.Element) {
		if element.Tag == tag && element.NamespaceURI() == namespace {
			result = append(result, element)
		}
		for _, child := range element.ChildElements() {
			walk(child)
		}
	}
	walk(root)
	return result
}

func elementsWithID(root *etree.Element, namespace, tag, id string) []*etree.Element {
	all := elementsByNamespace(root, namespace, tag)
	result := all[:0]
	for _, candidate := range all {
		if candidate.SelectAttrValue("Id", "") == id {
			result = append(result, candidate)
		}
	}
	return result
}

func elementsWithAnyID(root *etree.Element, id string) []*etree.Element {
	var result []*etree.Element
	var walk func(*etree.Element)
	walk = func(candidate *etree.Element) {
		if candidate.SelectAttrValue("Id", "") == id {
			result = append(result, candidate)
		}
		for _, child := range candidate.ChildElements() {
			walk(child)
		}
	}
	walk(root)
	return result
}

func exactlyOneChild(parent *etree.Element, namespace, tag string) (*etree.Element, error) {
	children := directChildren(parent, namespace, tag)
	if len(children) != 1 {
		return nil, fmt.Errorf("expected exactly one %s child, got %d", tag, len(children))
	}
	return children[0], nil
}

func requireMethod(parent *etree.Element, name, algorithm string) error {
	method, err := exactlyOneChild(parent, DSNamespace, name)
	if err != nil {
		return err
	}
	if actual := method.SelectAttrValue("Algorithm", ""); actual != algorithm {
		return fmt.Errorf("unsupported %s algorithm %q", name, actual)
	}
	return nil
}

func embeddedCertificates(signature *etree.Element) ([]*x509.Certificate, error) {
	keyInfo, err := exactlyOneChild(signature, DSNamespace, "KeyInfo")
	if err != nil {
		return nil, err
	}
	x509Data, err := exactlyOneChild(keyInfo, DSNamespace, "X509Data")
	if err != nil {
		return nil, err
	}
	certificates := directChildren(x509Data, DSNamespace, "X509Certificate")
	if len(certificates) == 0 {
		return nil, errors.New("KeyInfo contains no X509Certificate")
	}
	result := make([]*x509.Certificate, 0, len(certificates))
	for _, item := range certificates {
		der, err := decodeBase64Text(item, "X509Certificate")
		if err != nil {
			return nil, err
		}
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parse embedded certificate: %w", err)
		}
		result = append(result, certificate)
	}
	return result, nil
}

func decodeBase64Text(element *etree.Element, name string) ([]byte, error) {
	value := strings.Join(strings.Fields(element.Text()), "")
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", name, err)
	}
	return decoded, nil
}

func verifyReferenceAlgorithms(reference *etree.Element, document bool, suite AlgorithmSuite) error {
	if err := requireMethod(reference, "DigestMethod", suite.digestMethod); err != nil {
		return err
	}
	transforms, err := exactlyOneChild(reference, DSNamespace, "Transforms")
	if err != nil {
		return err
	}
	items := directChildren(transforms, DSNamespace, "Transform")
	expected := []string{suite.canonicalization}
	if document {
		expected = []string{EnvelopedSignatureMethod, suite.canonicalization}
	}
	if len(items) != len(expected) {
		return fmt.Errorf("reference has %d transforms, expected %d", len(items), len(expected))
	}
	for index, algorithm := range expected {
		if actual := items[index].SelectAttrValue("Algorithm", ""); actual != algorithm {
			return fmt.Errorf("unsupported reference transform %q", actual)
		}
	}
	return nil
}

func verifyDigest(canonicalizer dsig.Canonicalizer, hash crypto.Hash, element, reference *etree.Element) error {
	expectedElement, err := exactlyOneChild(reference, DSNamespace, "DigestValue")
	if err != nil {
		return err
	}
	expected, err := decodeBase64Text(expectedElement, "DigestValue")
	if err != nil {
		return err
	}
	actual, err := digestElement(canonicalizer, hash, element)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, actual) != 1 {
		return errors.New("digest mismatch")
	}
	return nil
}

func verifyQualifyingProperties(properties *etree.Element, certificate *x509.Certificate, suite AlgorithmSuite, allowLegacy bool) (time.Time, error) {
	signatureProperties, err := exactlyOneChild(properties, XAdESNamespace, "SignedSignatureProperties")
	if err != nil {
		return time.Time{}, err
	}
	timeElement, err := exactlyOneChild(signatureProperties, XAdESNamespace, "SigningTime")
	if err != nil {
		return time.Time{}, err
	}
	signingTime, err := time.Parse(time.RFC3339, strings.TrimSpace(timeElement.Text()))
	if err != nil {
		return time.Time{}, fmt.Errorf("parse XAdES SigningTime: %w", err)
	}
	signingCertificatesV2 := directChildren(signatureProperties, XAdESNamespace, "SigningCertificateV2")
	legacySigningCertificates := directChildren(signatureProperties, XAdESNamespace, "SigningCertificate")
	if len(signingCertificatesV2) == 1 && len(legacySigningCertificates) == 0 {
		if err := verifySigningCertificateDigest(signingCertificatesV2[0], certificate, suite); err != nil {
			return time.Time{}, err
		}
		return signingTime, nil
	}
	if !allowLegacy || len(legacySigningCertificates) != 1 || len(signingCertificatesV2) != 0 {
		return time.Time{}, errors.New("expected exactly one SigningCertificateV2 property")
	}
	if err := verifySigningCertificateDigest(legacySigningCertificates[0], certificate, suite); err != nil {
		return time.Time{}, err
	}
	cert, err := exactlyOneChild(legacySigningCertificates[0], XAdESNamespace, "Cert")
	if err != nil {
		return time.Time{}, err
	}
	issuerSerial, err := exactlyOneChild(cert, XAdESNamespace, "IssuerSerial")
	if err != nil {
		return time.Time{}, err
	}
	issuerName, err := exactlyOneChild(issuerSerial, DSNamespace, "X509IssuerName")
	if err != nil {
		return time.Time{}, err
	}
	serialNumber, err := exactlyOneChild(issuerSerial, DSNamespace, "X509SerialNumber")
	if err != nil {
		return time.Time{}, err
	}
	if !issuerNamesEqual(strings.TrimSpace(issuerName.Text()), certificate.Issuer) {
		return time.Time{}, errors.New("XAdES certificate issuer does not match embedded certificate")
	}
	wantedSerial := new(big.Int)
	if _, ok := wantedSerial.SetString(strings.TrimSpace(serialNumber.Text()), 10); !ok || wantedSerial.Cmp(certificate.SerialNumber) != 0 {
		return time.Time{}, errors.New("XAdES certificate serial does not match embedded certificate")
	}
	return signingTime, nil
}

func verifySigningCertificateDigest(signingCertificate *etree.Element, certificate *x509.Certificate, suite AlgorithmSuite) error {
	certs := directChildren(signingCertificate, XAdESNamespace, "Cert")
	if len(certs) != 1 {
		return fmt.Errorf("expected exactly one signing-certificate Cert, got %d", len(certs))
	}
	certDigest, err := exactlyOneChild(certs[0], XAdESNamespace, "CertDigest")
	if err != nil {
		return err
	}
	if err := requireMethod(certDigest, "DigestMethod", suite.digestMethod); err != nil {
		return err
	}
	digestValue, err := exactlyOneChild(certDigest, DSNamespace, "DigestValue")
	if err != nil {
		return err
	}
	expectedDigest, err := decodeBase64Text(digestValue, "certificate DigestValue")
	if err != nil {
		return err
	}
	actualDigest, err := digestBytes(suite.hash, certificate.Raw)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expectedDigest, actualDigest) != 1 {
		return errors.New("XAdES certificate digest does not match embedded certificate")
	}
	return nil
}

func issuerNamesEqual(value string, issuer pkix.Name) bool {
	return value == issuer.String()
}
