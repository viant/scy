package scy

import "sync"

type Registry struct {
	reg map[string]*Resource
	mux sync.RWMutex
}

func (r *Registry) Register(name string, resource *Resource) {
	r.mux.Lock()
	defer r.mux.Unlock()
	r.reg[name] = resource
}

func (r *Registry) Remove(name string) {
	r.mux.Lock()
	defer r.mux.Unlock()
	delete(r.reg, name)
}

func (r *Registry) Lookup(name string) *Resource {
	r.mux.RLock()
	defer r.mux.RUnlock()
	return r.reg[name]
}

var registry = &Registry{reg: map[string]*Resource{}}

//Resources returns resources registry
func Resources() *Registry {
	return registry
}
