package kms

import (
	"fmt"
	"sync"
)

// Register register cipher with supplied scheme
func Register(scheme string, service Cipher) {
	kms.register(scheme, service)
}

// Lookup looks up cipher for supplied scheme
func Lookup(scheme string) (Cipher, error) {
	return kms.lookup(scheme)
}

var kms = newRegistry()

type registry struct {
	mu       sync.RWMutex
	services map[string]Cipher
}

func newRegistry() *registry {
	return &registry{services: map[string]Cipher{}}
}

func (r *registry) register(scheme string, service Cipher) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.services[scheme] = service
}

func (r *registry) lookup(scheme string) (Cipher, error) {
	r.mu.RLock()
	srv, ok := r.services[scheme]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("failed to lookup kms for: %v", scheme)
	}
	return srv, nil
}
