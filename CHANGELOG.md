## Aug 26 2026

- Added support for loading read-only secrets from 1Password via `op://` URLs (requires `github.com/viant/afsc/op`).

## Aug 11 2026

- Added reusable X.509 `crypto.Signer` identities and PEM credential loading.
- Added protocol-neutral XAdES Baseline-B/EPES signing with modern `SigningCertificateV2`.
- Added whitelisted RSA, RSA-PSS, ECDSA, SHA-2, and canonicalization suites.
- Added enveloped, enveloping, and explicitly resolved detached signatures.
- Added explicit certificate trust, revocation, timestamp, policy, and long-term evidence interfaces.
- Added Scy KMS protection for inlined certificate private keys and passwords.
- Raised the minimum Go version to 1.23 for the patched XML canonicalization dependency.

## Feb 22 2022

## Feb 22 2022
- Initial release
