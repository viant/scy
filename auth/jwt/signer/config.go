package signer

import "github.com/viant/scy"

type Rule struct {
	Resource  []string      `json:",omitempty" yaml:"Resource,omitempty"`
	Algorithm string        `json:",omitempty" yaml:"Algorithm,omitempty"`
	Compact   bool          `json:",omitempty" yaml:"Compact,omitempty"`
	RSA       *scy.Resource `json:",omitempty" yaml:"RSA,omitempty"`
	HMAC      *scy.Resource `json:",omitempty" yaml:"HMAC,omitempty"`
}

type Config struct {
	RSA     *scy.Resource `json:",omitempty" yaml:"RSA,omitempty"`
	HMAC    *scy.Resource `json:",omitempty" yaml:"HMAC,omitempty"`
	Compact bool          `json:",omitempty" yaml:"Compact,omitempty"`
	Rules   []*Rule       `json:",omitempty" yaml:"Rules,omitempty"`
}
