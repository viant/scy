package xades

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
)

// TimestampClient obtains an RFC 3161 token for the supplied message imprint.
// Implementations own all TSA transport, authentication, and response checks.
type TimestampClient interface {
	Timestamp(ctx context.Context, imprint []byte, hash crypto.Hash) ([]byte, error)
}

// TimestampVerifier validates an RFC 3161 token, including its signature,
// trust path, policy, nonce (when applicable), and message-imprint binding.
type TimestampVerifier interface {
	VerifyTimestamp(ctx context.Context, token, imprint []byte, hash crypto.Hash, at time.Time) (time.Time, error)
}

// AddSignatureTimestamp upgrades a signed document with an XAdES signature
// timestamp. The supplied client must validate the TSA response before return.
func AddSignatureTimestamp(ctx context.Context, signedXML []byte, client TimestampClient, hash crypto.Hash) ([]byte, error) {
	if client == nil {
		return nil, errors.New("timestamp client is required")
	}
	if !hash.Available() {
		return nil, fmt.Errorf("timestamp hash %s is unavailable", hash)
	}
	doc, signature, err := parseSingleSignature(signedXML)
	if err != nil {
		return nil, err
	}
	if len(elementsByNamespace(signature, XAdESNamespace, "SignatureTimeStamp")) != 0 {
		return nil, errors.New("signature already contains a SignatureTimeStamp")
	}
	signatureValue, err := exactlyOneChild(signature, DSNamespace, "SignatureValue")
	if err != nil {
		return nil, err
	}
	imprint, err := signatureValueImprint(signatureValue, hash)
	if err != nil {
		return nil, err
	}
	token, err := client.Timestamp(ctx, imprint, hash)
	if err != nil {
		return nil, fmt.Errorf("obtain signature timestamp: %w", err)
	}
	if len(token) == 0 {
		return nil, errors.New("timestamp client returned an empty token")
	}
	unsignedSignatureProperties, err := ensureUnsignedSignatureProperties(signature)
	if err != nil {
		return nil, err
	}
	timestamp := element("xades", "SignatureTimeStamp")
	unsignedSignatureProperties.AddChild(timestamp)
	method(timestamp, "CanonicalizationMethod", ExclusiveCanonicalization)
	child(timestamp, "xades", "EncapsulatedTimeStamp", base64.StdEncoding.EncodeToString(token))
	result, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize timestamped XML: %w", err)
	}
	return result, nil
}

func verifySignatureTimestamp(ctx context.Context, signature *etree.Element, verifier TimestampVerifier, hash crypto.Hash, at time.Time, required bool) (*time.Time, error) {
	timestamps := elementsByNamespace(signature, XAdESNamespace, "SignatureTimeStamp")
	if len(timestamps) == 0 {
		if required {
			return nil, errors.New("XAdES signature timestamp is required")
		}
		return nil, nil
	}
	if len(timestamps) != 1 {
		return nil, fmt.Errorf("expected at most one SignatureTimeStamp, got %d", len(timestamps))
	}
	if verifier == nil {
		return nil, errors.New("signature contains a timestamp but no TimestampVerifier was configured")
	}
	timestamp := timestamps[0]
	if !hasAncestor(timestamp, XAdESNamespace, "UnsignedSignatureProperties") {
		return nil, errors.New("SignatureTimeStamp is outside UnsignedSignatureProperties")
	}
	if err := requireMethod(timestamp, "CanonicalizationMethod", ExclusiveCanonicalization); err != nil {
		return nil, err
	}
	encapsulated, err := exactlyOneChild(timestamp, XAdESNamespace, "EncapsulatedTimeStamp")
	if err != nil {
		return nil, err
	}
	token, err := decodeBase64Text(encapsulated, "EncapsulatedTimeStamp")
	if err != nil {
		return nil, err
	}
	signatureValue, err := exactlyOneChild(signature, DSNamespace, "SignatureValue")
	if err != nil {
		return nil, err
	}
	imprint, err := signatureValueImprint(signatureValue, hash)
	if err != nil {
		return nil, err
	}
	timestampTime, err := verifier.VerifyTimestamp(ctx, token, imprint, hash, at)
	if err != nil {
		return nil, fmt.Errorf("verify signature timestamp: %w", err)
	}
	return &timestampTime, nil
}

func hasAncestor(element *etree.Element, namespace, tag string) bool {
	for parent := element.Parent(); parent != nil; parent = parent.Parent() {
		if parent.NamespaceURI() == namespace && parent.Tag == tag {
			return true
		}
	}
	return false
}

func signatureValueImprint(signatureValue *etree.Element, hash crypto.Hash) ([]byte, error) {
	copy := signatureValue.Copy()
	if copy.SelectAttr("xmlns:ds") == nil {
		copy.CreateAttr("xmlns:ds", DSNamespace)
	}
	canonicalizer, _ := SuiteSHA256Exclusive.canonicalizer()
	canonical, err := canonicalizer.Canonicalize(copy)
	if err != nil {
		return nil, fmt.Errorf("canonicalize SignatureValue: %w", err)
	}
	return digestBytes(hash, canonical)
}

func parseSingleSignature(data []byte) (*etree.Document, *etree.Element, error) {
	doc, err := parseXML(data, DefaultMaxDocumentBytes, DefaultMaxXMLDepth, "signed XML")
	if err != nil {
		return nil, nil, err
	}
	signatures := elementsByNamespace(doc.Root(), DSNamespace, "Signature")
	if len(signatures) != 1 {
		return nil, nil, fmt.Errorf("expected exactly one XML Signature, got %d", len(signatures))
	}
	return doc, signatures[0], nil
}

func ensureUnsignedSignatureProperties(signature *etree.Element) (*etree.Element, error) {
	qualifying := elementsByNamespace(signature, XAdESNamespace, "QualifyingProperties")
	if len(qualifying) != 1 {
		return nil, fmt.Errorf("expected exactly one QualifyingProperties, got %d", len(qualifying))
	}
	unsigned := directChildren(qualifying[0], XAdESNamespace, "UnsignedProperties")
	var unsignedProperties *etree.Element
	if len(unsigned) == 0 {
		unsignedProperties = element("xades", "UnsignedProperties")
		qualifying[0].AddChild(unsignedProperties)
	} else if len(unsigned) == 1 {
		unsignedProperties = unsigned[0]
	} else {
		return nil, errors.New("multiple UnsignedProperties elements")
	}
	properties := directChildren(unsignedProperties, XAdESNamespace, "UnsignedSignatureProperties")
	if len(properties) == 0 {
		result := element("xades", "UnsignedSignatureProperties")
		unsignedProperties.AddChild(result)
		return result, nil
	}
	if len(properties) != 1 {
		return nil, errors.New("multiple UnsignedSignatureProperties elements")
	}
	return properties[0], nil
}
