package kms

import "context"

//Cipher defines cipher interface
type Cipher interface {
	//Decrypt decrypts data with supplied key
	Decrypt(ctx context.Context, key *Key, data []byte) ([]byte, error)

	//Encrypt encrypts data with supplied key
	Encrypt(ctx context.Context, key *Key, data []byte) ([]byte, error)
}
