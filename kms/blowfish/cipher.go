package blowfish

import (
	"context"
	"crypto/cipher"
	"cryp
	"fmt"
	"github.com/viant/scy/kms"
	"golang.org/x/crypto/blowfish"
)

// legalBlowfishKey returns a key ≤ 56 bytes.
// If src is already ≤ 56 bytes it’s used verbatim.
// Otherwise a 32-byte SHA-256 digest is returned.
func EnsureKey(src []byte) []byte {
	if len(src) <= 56 {
		return src
	}
	sum := sha256.Sum256(src) // [32]byte
	return sum[:]             // ← 32-byte slice
}

const scheme = "blowfish"

var defaultKey = []byte{0x24, 0x66, 0xDD, 0x87, 0x8B, 0x96, 0x3C, 0x9D}

func blowfishCheckSizeAndPad(padded []byte) []byte {
	modulus := len(padded) % blowfish.BlockSize
	if modulus != 0 {
		padlen := blowfish.BlockSize - modulus
		for i := 0; i < padlen; i++ {
			padded = append(padded, 0)
		}
	}
	return padded
}

// Cipher represents blowfish cipher
type Cipher struct{}

// Encrypt encrypts data with supplied key
func (b *Cipher) Encrypt(ctx context.Context, key *kms.Key, data []byte) ([]byte, error) {
	cipherKey, err := key.Key(ctx, defaultKey)
	if err != nil {
		return nil, err
	}
	blowfishCipher, err := blowfish.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	paddedSource := blowfishCheckSizeAndPad(data)
	ciphertext := make([]byte, blowfish.BlockSize+len(paddedSource))
	eiv := ciphertext[:blowfish.BlockSize]
	encodedBlackEncryptor := cipher.NewCBCEncrypter(blowfishCipher, eiv)
	encodedBlackEncryptor.CryptBlocks(ciphertext[blowfish.BlockSize:], paddedSource)
	return ciphertext, nil
}

// Decrypt decrypts data with supplied key
func (b *Cipher) Decrypt(ctx context.Context, key *kms.Key, data []byte) ([]byte, error) {
	cipherKey, err := key.Key(ctx, defaultKey)
	if err != nil {
		return nil, err
	}
	blowfishCipher, err := blowfish.NewCipher(cipherKey)
	if err != nil {
		return nil, err
	}
	div := data[:blowfish.BlockSize]
	decrypted := data[blowfish.BlockSize:]
	if len(decrypted)%blowfish.BlockSize != 0 {
		return nil, fmt.Errorf("decrypted is not a multiple of blowfish.BlockSize")
	}
	dcbc := cipher.NewCBCDecrypter(blowfishCipher, div)
	dcbc.CryptBlocks(decrypted, decrypted)
	var result = make([]byte, 0)
	for _, b := range decrypted {
		if b == 0x0 {
			break
		}
		result = append(result, b)
	}
	return result, nil
}
