package gcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
	"google.golang.org/api/cloudkms/v1"
	"google.golang.org/api/option"
)

//Schema represents gcp cipher scheme
const Schema = "gcp"

//Cipher represents gcp cipher
type Cipher struct {
	*cloudkms.Service
}

//Encrypt encrypts plainText with supplied key
func (s *Cipher) Encrypt(ctx context.Context, key *kms.Key, data []byte) ([]byte, error) {
	service := cloudkms.NewProjectsLocationsKeyRingsCryptoKeysService(s.Service)
	encoded := base64.StdEncoding.EncodeToString(data)
	response, err := service.Encrypt(s.normalizeKeyPath(key.Path), &cloudkms.EncryptRequest{Plaintext: encoded}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with key %v, %w", key.Path, err)
	}
	return []byte(response.Ciphertext), nil
}

//Decrypt decrypts plainText with supplied key
func (s *Cipher) Decrypt(ctx context.Context, key *kms.Key, data []byte) ([]byte, error) {
	service := cloudkms.NewProjectsLocationsKeyRingsCryptoKeysService(s.Service)
	response, err := service.Decrypt(s.normalizeKeyPath(key.Path), &cloudkms.DecryptRequest{Ciphertext: string(data)}).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt with key %v, %w", key.Path, err)
	}
	encoded, err := base64.StdEncoding.DecodeString(response.Plaintext)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (s *Cipher) normalizeKeyPath(keyPath string) string {
	if keyPath[0] == '/' {
		return keyPath[1:]
	}
	return keyPath
}

//New creates gcp  cipher
func New(ctx context.Context, opts ...option.ClientOption) (*Cipher, error) {
	opts = append(opts, option.WithScopes(cloudkms.CloudPlatformScope, cloudkms.CloudkmsScope))
	kmsService, err := cloudkms.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create kmsService server for key, %w", err)
	}
	return &Cipher{Service: kmsService}, nil
}
