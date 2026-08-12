package xades

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/beevik/etree"
)

// SignaturePolicy identifies and hashes an external signature policy for an
// XAdES-EPES signature. Digest must be computed using the signature suite hash.
type SignaturePolicy struct {
	Identifier  string
	Description string
	Digest      []byte
}

// PolicyResolver supplies policy bytes for verification. Scy never resolves a
// policy identifier automatically.
type PolicyResolver interface {
	ResolvePolicy(ctx context.Context, identifier string) ([]byte, error)
}

type PolicyResolverFunc func(ctx context.Context, identifier string) ([]byte, error)

func (f PolicyResolverFunc) ResolvePolicy(ctx context.Context, identifier string) ([]byte, error) {
	return f(ctx, identifier)
}

func addSignaturePolicy(parent *etree.Element, policy *SignaturePolicy, suite AlgorithmSuite) error {
	if policy == nil {
		return nil
	}
	if strings.TrimSpace(policy.Identifier) == "" {
		return errors.New("signature policy identifier is required")
	}
	if len(policy.Digest) != suite.hash.Size() {
		return fmt.Errorf("signature policy digest must be %d bytes for %s", suite.hash.Size(), suite.hash)
	}
	identifier := element("xades", "SignaturePolicyIdentifier")
	parent.AddChild(identifier)
	policyID := element("xades", "SignaturePolicyId")
	identifier.AddChild(policyID)
	sigPolicyID := element("xades", "SigPolicyId")
	policyID.AddChild(sigPolicyID)
	child(sigPolicyID, "xades", "Identifier", policy.Identifier)
	if policy.Description != "" {
		child(sigPolicyID, "xades", "Description", policy.Description)
	}
	policyHash := element("xades", "SigPolicyHash")
	policyID.AddChild(policyHash)
	method(policyHash, "DigestMethod", suite.digestMethod)
	child(policyHash, "ds", "DigestValue", base64.StdEncoding.EncodeToString(policy.Digest))
	return nil
}

func verifySignaturePolicy(ctx context.Context, properties *etree.Element, suite AlgorithmSuite, resolver PolicyResolver, required bool) (*SignaturePolicy, error) {
	container := directChildren(properties, XAdESNamespace, "SignaturePolicyIdentifier")
	if len(container) == 0 {
		if required {
			return nil, errors.New("XAdES signature policy is required")
		}
		return nil, nil
	}
	if len(container) != 1 {
		return nil, errors.New("multiple SignaturePolicyIdentifier properties")
	}
	policyID, err := exactlyOneChild(container[0], XAdESNamespace, "SignaturePolicyId")
	if err != nil {
		return nil, err
	}
	sigPolicyID, err := exactlyOneChild(policyID, XAdESNamespace, "SigPolicyId")
	if err != nil {
		return nil, err
	}
	identifierElement, err := exactlyOneChild(sigPolicyID, XAdESNamespace, "Identifier")
	if err != nil {
		return nil, err
	}
	identifier := strings.TrimSpace(identifierElement.Text())
	if identifier == "" {
		return nil, errors.New("signature policy identifier is empty")
	}
	description := ""
	descriptions := directChildren(sigPolicyID, XAdESNamespace, "Description")
	if len(descriptions) > 1 {
		return nil, errors.New("multiple signature policy descriptions")
	}
	if len(descriptions) == 1 {
		description = strings.TrimSpace(descriptions[0].Text())
	}
	policyHash, err := exactlyOneChild(policyID, XAdESNamespace, "SigPolicyHash")
	if err != nil {
		return nil, err
	}
	if err := requireMethod(policyHash, "DigestMethod", suite.digestMethod); err != nil {
		return nil, err
	}
	digestValue, err := exactlyOneChild(policyHash, DSNamespace, "DigestValue")
	if err != nil {
		return nil, err
	}
	digest, err := decodeBase64Text(digestValue, "signature policy DigestValue")
	if err != nil {
		return nil, err
	}
	if len(digest) != suite.hash.Size() {
		return nil, errors.New("signature policy digest has an invalid length")
	}
	result := &SignaturePolicy{Identifier: identifier, Description: description, Digest: digest}
	if resolver == nil {
		return result, nil
	}
	policyDocument, err := resolver.ResolvePolicy(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("resolve signature policy %q: %w", identifier, err)
	}
	actual, err := digestBytes(suite.hash, policyDocument)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(digest, actual) != 1 {
		return nil, errors.New("signature policy digest mismatch")
	}
	return result, nil
}
