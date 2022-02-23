package kms

import "fmt"

//Register register cipher with supplied scheme
func Register(scheme string, service Cipher) {
	kms.register(scheme, service)
}

//Lookup lookups cipher for supplied scheme
func Lookup(scheme string) (Cipher, error) {
	return kms.lookup(scheme)
}

var kms = registry{}

type registry map[string]Cipher

func (r registry) register(scheme string, service Cipher) {
	r[scheme] = service
}

func (r registry) lookup(scheme string) (Cipher, error) {
	srv, ok := r[scheme]
	if !ok {
		return nil, fmt.Errorf("failed to lookup kms for: %v", scheme)
	}
	return srv, nil
}
