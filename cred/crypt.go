package cred

import (
	"context"
	"encoding/base64"
	"fmt"
	"github.com/viant/scy/kms"
)

func encrypt(ctx context.Context, key *kms.Key, cipher kms.Cipher, value, encryptedValue *string) error {
	encryptedKey, err := cipher.Encrypt(ctx, key, []byte(*value))
	if err != nil {
		return fmt.Errorf("failed to encryptedKey")
	}
	var base64Encoded = make([]byte, base64.StdEncoding.EncodedLen(len(encryptedKey)))
	base64.StdEncoding.Encode(base64Encoded, encryptedKey)
	*encryptedValue = string(base64Encoded)
	*value = ""
	return nil
}
func decrypt(ctx context.Context, key *kms.Key, cipher kms.Cipher, encryptedValue, value *string) error {
	encrypted, err := base64.StdEncoding.DecodeString(*encryptedValue)
	if err != nil {
		return fmt.Errorf("failed to decrypt DecodeString")
	}
	decrypted, err := cipher.Decrypt(ctx, key, encrypted)
	if err != nil {
		return fmt.Errorf("failed to decrypt")
	}
	*value = string(decrypted)
	*encryptedValue = ""
	return nil
}
