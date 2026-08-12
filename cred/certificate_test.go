package cred

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/viant/scy/kms"
)

func TestCertificateCipherRoundTrip(t *testing.T) {
	const scheme = "certificate-test"
	kms.Register(scheme, xorCipher{})
	key := &kms.Key{Scheme: scheme}
	credential := &Certificate{
		PrivateKeyPEM:      []byte("private-key"),
		PrivateKeyPassword: "password",
	}

	require.NoError(t, credential.Cipher(context.Background(), key))
	require.Empty(t, credential.PrivateKeyPEM)
	require.Empty(t, credential.PrivateKeyPassword)
	require.NotEmpty(t, credential.EncryptedPrivateKey)
	require.NotEmpty(t, credential.EncryptedPrivateKeyPassword)

	require.NoError(t, credential.Decipher(context.Background(), key))
	require.Equal(t, []byte("private-key"), credential.PrivateKeyPEM)
	require.Equal(t, "password", credential.PrivateKeyPassword)
	require.Empty(t, credential.EncryptedPrivateKey)
	require.Empty(t, credential.EncryptedPrivateKeyPassword)
}

func TestTargetTypeCertificate(t *testing.T) {
	target, err := TargetType("x509")
	require.NoError(t, err)
	require.Equal(t, "Certificate", target.Name())
}

type xorCipher struct{}

func (xorCipher) Encrypt(_ context.Context, _ *kms.Key, data []byte) ([]byte, error) {
	return xor(data), nil
}

func (xorCipher) Decrypt(_ context.Context, _ *kms.Key, data []byte) ([]byte, error) {
	return xor(data), nil
}

func xor(data []byte) []byte {
	result := make([]byte, len(data))
	for index, value := range data {
		result[index] = value ^ 0x5a
	}
	return result
}
