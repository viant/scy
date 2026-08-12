# XAdES toolkit

Package `auth/xades` provides protocol-neutral XAdES signing and verification.
It uses strict profiles and caller-owned trust services instead of resolving
untrusted URIs or making network requests from the XML verifier.

## Supported capabilities

- XAdES Baseline-B generation with `SigningCertificateV2`
- XAdES-EPES explicit signature policies
- enveloped, enveloping, and detached packaging
- RSA PKCS#1 v1.5, RSA-PSS, and ECDSA signatures
- SHA-256, SHA-384, and SHA-512 safe suites
- Exclusive Canonical XML 1.0 and Canonical XML 1.1
- explicit X.509 trust roots, intermediates, key usages, and verification time
- caller-provided revocation checks without implicit network access
- RFC 3161 timestamp client and verifier boundaries for Baseline-T
- validated certificate, OCSP, and CRL evidence containers for long-term validation
- legacy `SigningCertificate` verification only when explicitly enabled

Archive timestamp renewal and automatic trust-service discovery are not
implemented. Those functions require application-specific retention, trust,
and network policy and should be layered on the interfaces in this package.

## Baseline-B

```go
identity, err := signing.NewIdentityPEM(certificatePEM, privateKeyPEM, password)
if err != nil {
    return err
}

signed, err := xades.SignEnveloped(document, identity, &xades.Options{
    Suite: xades.SuitePSSSHA256Exclusive,
})
```

New signatures use `SigningCertificateV2`. `SignEnveloping` embeds the signed
XML in a `ds:Object`. `SignDetached` signs external XML but only records its URI;
it does not dereference that URI.

## Detached verification

Detached content must be supplied by an explicit resolver:

```go
result, err := xades.VerifyWithOptions(ctx, signature, &xades.ValidationOptions{
    Resolver: xades.ResolverFunc(func(ctx context.Context, uri string) ([]byte, error) {
        return trustedDocumentStore.Load(ctx, uri)
    }),
})
```

The resolver should enforce its own URI allowlist, size limit, timeout, and
authorization policy. Scy never falls back to HTTP, filesystem, or other URI
resolution.

## Certificate trust and revocation

Cryptographic signature validity and certificate trust are separate checks.
Configure trust explicitly when trust is required:

```go
result, err := xades.VerifyWithOptions(ctx, signed, &xades.ValidationOptions{
    Time: verificationTime,
    Trust: &xades.TrustPolicy{
        Roots:          roots,
        Intermediates:  intermediates,
        KeyUsages:      []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
        Revocation:     revocationChecker,
    },
})
```

`UseSystemRoots` must be enabled deliberately. A `RevocationChecker` receives
the already constructed certificate path and can use stapled evidence, local
caches, OCSP, or CRLs. The XML verifier itself never performs network I/O.

## Signature policies

To create an EPES signature, hash the authoritative policy document with the
selected suite and supply its identifier and digest. During verification, a
`PolicyResolver` can provide the authoritative bytes; Scy compares their digest
with the signed property.

## Timestamps and long-term evidence

`AddSignatureTimestamp` adds an XAdES `SignatureTimeStamp` using a caller-owned
`TimestampClient`. `VerifyWithOptions` requires a `TimestampVerifier` whenever a
timestamp is present. The verifier is responsible for RFC 3161 token signature,
policy, nonce, TSA chain, time, and message-imprint validation.

`AddLongTermValidationEvidence` only embeds material after an `EvidenceValidator`
accepts it and requires a signature timestamp. Verification likewise rejects
embedded evidence unless a validator is configured. This keeps OCSP, CRL, and
trust-network policy outside XML parsing.

## Verification safety

- Only built-in `AlgorithmSuite` values or values returned by `SafeSuite` work.
- Arbitrary transform and canonicalization URIs are rejected.
- Signatures must contain exactly one data reference and one
  `SignedProperties` reference.
- Same-document object IDs must resolve uniquely.
- Detached references require an explicit resolver.
- Embedded timestamps and long-term evidence require explicit validators.
- Certificate pinning and certificate-path trust can be required independently.
- Signed and detached XML inputs have default 32 MiB and 256-level depth limits;
  callers can lower them through signing and validation options.

Applications should generally lower these limits to match their document profile
when XML can be supplied by untrusted parties.
