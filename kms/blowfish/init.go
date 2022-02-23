package blowfish

import "github.com/viant/scy/kms"

func init() {
	kms.Register(scheme, &Cipher{})
}
