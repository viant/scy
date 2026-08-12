package xades

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/beevik/etree"
)

// ValidationEvidence contains caller-acquired certificate and revocation
// material for long-term validation. Scy never fetches this material itself.
type ValidationEvidence struct {
	Certificates  []*x509.Certificate
	OCSPResponses [][]byte
	CRLs          [][]byte
}

// EvidenceValidator validates long-term evidence against the signing path.
// Implementations decide accepted OCSP/CRL policies and trust anchors.
type EvidenceValidator interface {
	ValidateEvidence(ctx context.Context, evidence *ValidationEvidence, signingChain []*x509.Certificate, at time.Time) error
}

// AddLongTermValidationEvidence embeds prevalidated certificate and revocation
// material. A signature timestamp and an EvidenceValidator are required.
func AddLongTermValidationEvidence(ctx context.Context, signedXML []byte, evidence *ValidationEvidence, validator EvidenceValidator, at time.Time) ([]byte, error) {
	if evidence == nil {
		return nil, errors.New("validation evidence is required")
	}
	if validator == nil {
		return nil, errors.New("evidence validator is required")
	}
	doc, signature, err := parseSingleSignature(signedXML)
	if err != nil {
		return nil, err
	}
	if len(elementsByNamespace(signature, XAdESNamespace, "SignatureTimeStamp")) == 0 {
		return nil, errors.New("long-term validation evidence requires a signature timestamp")
	}
	chain, err := embeddedCertificates(signature)
	if err != nil {
		return nil, err
	}
	if err := validator.ValidateEvidence(ctx, evidence, chain, at); err != nil {
		return nil, fmt.Errorf("validate long-term evidence: %w", err)
	}
	unsigned, err := ensureUnsignedSignatureProperties(signature)
	if err != nil {
		return nil, err
	}
	if len(directChildren(unsigned, XAdESNamespace, "CertificateValues")) != 0 || len(directChildren(unsigned, XAdESNamespace, "RevocationValues")) != 0 {
		return nil, errors.New("signature already contains long-term validation evidence")
	}
	if len(evidence.Certificates) > 0 {
		certificateValues := element("xades", "CertificateValues")
		unsigned.AddChild(certificateValues)
		for _, certificate := range evidence.Certificates {
			if certificate == nil {
				return nil, errors.New("validation evidence contains a nil certificate")
			}
			child(certificateValues, "xades", "EncapsulatedX509Certificate", base64.StdEncoding.EncodeToString(certificate.Raw))
		}
	}
	if len(evidence.OCSPResponses) > 0 || len(evidence.CRLs) > 0 {
		revocationValues := element("xades", "RevocationValues")
		unsigned.AddChild(revocationValues)
		if len(evidence.CRLs) > 0 {
			crlValues := element("xades", "CRLValues")
			revocationValues.AddChild(crlValues)
			for _, value := range evidence.CRLs {
				child(crlValues, "xades", "EncapsulatedCRLValue", base64.StdEncoding.EncodeToString(value))
			}
		}
		if len(evidence.OCSPResponses) > 0 {
			ocspValues := element("xades", "OCSPValues")
			revocationValues.AddChild(ocspValues)
			for _, value := range evidence.OCSPResponses {
				child(ocspValues, "xades", "EncapsulatedOCSPValue", base64.StdEncoding.EncodeToString(value))
			}
		}
	}
	result, err := doc.WriteToBytes()
	if err != nil {
		return nil, fmt.Errorf("serialize long-term XAdES evidence: %w", err)
	}
	return result, nil
}

func verifyLongTermEvidence(ctx context.Context, signature *etree.Element, chain []*x509.Certificate, validator EvidenceValidator, at time.Time, required bool) (*ValidationEvidence, error) {
	certificateValues := elementsByNamespace(signature, XAdESNamespace, "CertificateValues")
	revocationValues := elementsByNamespace(signature, XAdESNamespace, "RevocationValues")
	if len(certificateValues) == 0 && len(revocationValues) == 0 {
		if required {
			return nil, errors.New("long-term validation evidence is required")
		}
		return nil, nil
	}
	if len(certificateValues) > 1 || len(revocationValues) > 1 {
		return nil, errors.New("multiple long-term validation evidence containers")
	}
	if len(certificateValues) == 1 && !hasAncestor(certificateValues[0], XAdESNamespace, "UnsignedSignatureProperties") {
		return nil, errors.New("CertificateValues is outside UnsignedSignatureProperties")
	}
	if len(revocationValues) == 1 && !hasAncestor(revocationValues[0], XAdESNamespace, "UnsignedSignatureProperties") {
		return nil, errors.New("RevocationValues is outside UnsignedSignatureProperties")
	}
	if validator == nil {
		return nil, errors.New("signature contains long-term evidence but no EvidenceValidator was configured")
	}
	evidence := &ValidationEvidence{}
	if len(certificateValues) == 1 {
		for _, item := range directChildren(certificateValues[0], XAdESNamespace, "EncapsulatedX509Certificate") {
			der, err := decodeBase64Text(item, "EncapsulatedX509Certificate")
			if err != nil {
				return nil, err
			}
			certificate, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("parse validation-evidence certificate: %w", err)
			}
			evidence.Certificates = append(evidence.Certificates, certificate)
		}
	}
	if len(revocationValues) == 1 {
		for _, item := range elementsByNamespace(revocationValues[0], XAdESNamespace, "EncapsulatedOCSPValue") {
			value, err := decodeBase64Text(item, "EncapsulatedOCSPValue")
			if err != nil {
				return nil, err
			}
			evidence.OCSPResponses = append(evidence.OCSPResponses, value)
		}
		for _, item := range elementsByNamespace(revocationValues[0], XAdESNamespace, "EncapsulatedCRLValue") {
			value, err := decodeBase64Text(item, "EncapsulatedCRLValue")
			if err != nil {
				return nil, err
			}
			evidence.CRLs = append(evidence.CRLs, value)
		}
	}
	if err := validator.ValidateEvidence(ctx, evidence, chain, at); err != nil {
		return nil, fmt.Errorf("validate embedded long-term evidence: %w", err)
	}
	return evidence, nil
}
