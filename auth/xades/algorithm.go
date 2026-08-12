package xades

import (
	"crypto"
	_ "crypto/sha512"
	"errors"
	"fmt"

	dsig "github.com/russellhaering/goxmldsig"
)

const (
	CanonicalXML10Method      = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	CanonicalXML11Method      = "http://www.w3.org/2006/12/xml-c14n11"
	ExclusiveCanonicalization = "http://www.w3.org/2001/10/xml-exc-c14n#"

	DigestMethodSHA384 = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	DigestMethodSHA512 = "http://www.w3.org/2001/04/xmlenc#sha512"

	SignatureMethodRSA384   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	SignatureMethodRSA512   = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	SignatureMethodPSS256   = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	SignatureMethodPSS384   = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
	SignatureMethodPSS512   = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"
	SignatureMethodECDSA384 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	SignatureMethodECDSA512 = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"
)

// AlgorithmSuite is a closed, validated combination of XML canonicalization,
// digest, and signature algorithms. Construct suites with one of the exported
// constructors; its fields are intentionally private to prevent unsafe URIs.
type AlgorithmSuite struct {
	name             string
	hash             crypto.Hash
	digestMethod     string
	canonicalization string
	rsaMethod        string
	ecdsaMethod      string
	rsaPSS           bool
}

func (s AlgorithmSuite) Name() string                   { return s.name }
func (s AlgorithmSuite) Hash() crypto.Hash              { return s.hash }
func (s AlgorithmSuite) DigestMethod() string           { return s.digestMethod }
func (s AlgorithmSuite) CanonicalizationMethod() string { return s.canonicalization }

// SafeSuite returns a whitelisted suite. Supported hashes are SHA-256,
// SHA-384, and SHA-512. Canonicalization is limited to Exclusive C14N 1.0,
// Canonical XML 1.0, or Canonical XML 1.1.
func SafeSuite(hash crypto.Hash, canonicalization string, rsaPSS bool) (AlgorithmSuite, error) {
	result := AlgorithmSuite{hash: hash, canonicalization: canonicalization, rsaPSS: rsaPSS}
	switch hash {
	case crypto.SHA256:
		result.digestMethod = DigestMethodSHA256
		result.ecdsaMethod = SignatureMethodECDSA256
		if rsaPSS {
			result.rsaMethod = SignatureMethodPSS256
		} else {
			result.rsaMethod = SignatureMethodRSA256
		}
	case crypto.SHA384:
		result.digestMethod = DigestMethodSHA384
		result.ecdsaMethod = SignatureMethodECDSA384
		if rsaPSS {
			result.rsaMethod = SignatureMethodPSS384
		} else {
			result.rsaMethod = SignatureMethodRSA384
		}
	case crypto.SHA512:
		result.digestMethod = DigestMethodSHA512
		result.ecdsaMethod = SignatureMethodECDSA512
		if rsaPSS {
			result.rsaMethod = SignatureMethodPSS512
		} else {
			result.rsaMethod = SignatureMethodRSA512
		}
	default:
		return AlgorithmSuite{}, fmt.Errorf("unsupported digest hash %v", hash)
	}
	switch canonicalization {
	case ExclusiveCanonicalization, CanonicalXML10Method, CanonicalXML11Method:
	default:
		return AlgorithmSuite{}, fmt.Errorf("unsupported canonicalization method %q", canonicalization)
	}
	mode := "pkcs1"
	if rsaPSS {
		mode = "pss"
	}
	result.name = fmt.Sprintf("%s-%s-%s", hash.String(), mode, canonicalizationName(canonicalization))
	return result, nil
}

func MustSafeSuite(hash crypto.Hash, canonicalization string, rsaPSS bool) AlgorithmSuite {
	suite, err := SafeSuite(hash, canonicalization, rsaPSS)
	if err != nil {
		panic(err)
	}
	return suite
}

var (
	SuiteSHA256Exclusive    = MustSafeSuite(crypto.SHA256, ExclusiveCanonicalization, false)
	SuiteSHA384Exclusive    = MustSafeSuite(crypto.SHA384, ExclusiveCanonicalization, false)
	SuiteSHA512Exclusive    = MustSafeSuite(crypto.SHA512, ExclusiveCanonicalization, false)
	SuitePSSSHA256Exclusive = MustSafeSuite(crypto.SHA256, ExclusiveCanonicalization, true)
	SuitePSSSHA384Exclusive = MustSafeSuite(crypto.SHA384, ExclusiveCanonicalization, true)
	SuitePSSSHA512Exclusive = MustSafeSuite(crypto.SHA512, ExclusiveCanonicalization, true)
	SuiteSHA256C14N11       = MustSafeSuite(crypto.SHA256, CanonicalXML11Method, false)
)

// StandardSuites returns all suites accepted by default verification. The
// returned slice is a copy and can safely be modified by callers.
func StandardSuites() []AlgorithmSuite {
	return []AlgorithmSuite{
		SuiteSHA256Exclusive,
		SuiteSHA384Exclusive,
		SuiteSHA512Exclusive,
		SuitePSSSHA256Exclusive,
		SuitePSSSHA384Exclusive,
		SuitePSSSHA512Exclusive,
		SuiteSHA256C14N11,
	}
}

func canonicalizationName(value string) string {
	switch value {
	case ExclusiveCanonicalization:
		return "exc-c14n10"
	case CanonicalXML10Method:
		return "c14n10"
	case CanonicalXML11Method:
		return "c14n11"
	default:
		return "unknown"
	}
}

func (s AlgorithmSuite) canonicalizer() (dsig.Canonicalizer, error) {
	switch s.canonicalization {
	case ExclusiveCanonicalization:
		return dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList(""), nil
	case CanonicalXML10Method:
		return dsig.MakeC14N10RecCanonicalizer(), nil
	case CanonicalXML11Method:
		return dsig.MakeC14N11Canonicalizer(), nil
	default:
		return nil, fmt.Errorf("unsupported canonicalization method %q", s.canonicalization)
	}
}

func (s AlgorithmSuite) validate() error {
	if s.hash == 0 || s.digestMethod == "" || s.canonicalization == "" || s.rsaMethod == "" || s.ecdsaMethod == "" {
		return errors.New("invalid zero-value AlgorithmSuite; use SafeSuite")
	}
	if !s.hash.Available() {
		return fmt.Errorf("hash %s is unavailable", s.hash)
	}
	return nil
}

func selectSuite(suites []AlgorithmSuite, canonicalization, digestMethod, signatureMethod string) (AlgorithmSuite, error) {
	for _, suite := range suites {
		if suite.canonicalization != canonicalization || suite.digestMethod != digestMethod {
			continue
		}
		if suite.rsaMethod == signatureMethod || suite.ecdsaMethod == signatureMethod {
			return suite, suite.validate()
		}
	}
	return AlgorithmSuite{}, fmt.Errorf("signature algorithm combination is not allowed: canonicalization=%q digest=%q signature=%q", canonicalization, digestMethod, signatureMethod)
}
