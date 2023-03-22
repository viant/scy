package signer

import "github.com/viant/scy"

type Config struct {
	RSA  *scy.Resource
	HMAC *scy.Resource
}
