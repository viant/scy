package kms

import "context"

//Securable interface defininf operation to cipher/decipher sensitive data points
type Securable interface {
	Cipher(ctx context.Context, key *Key) error
	Decipher(ctx context.Context, key *Key) error
}
