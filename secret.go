package scy

import (
	"encoding/json"
	"fmt"
	"github.com/viant/toolbox/data"
)

//Secret represent secret
type Secret struct {
	*Resource
	Target  interface{}
	payload []byte
	IsPlain bool
}

//Validate checks if secrt is valid
func (s *Secret) Validate() error {
	if len(s.payload) == 0 && s.Target == nil {
		return fmt.Errorf("payload was empty")
	}
	return s.Resource.Validate()
}

//String returns secret literal
func (s *Secret) String() string {
	return string(s.payload)
}

//Decode secret into target
func (s *Secret) Decode(target interface{}) error {
	return json.Unmarshal(s.payload, target)
}

//Expand expend text with secret data
func (s *Secret) Expand(text string) string {
	var replacement = data.NewMap()
	if s.IsPlain {
		replacement[s.Name] = string(s.payload)
	} else {
		kvParis := map[string]interface{}{}
		_ = s.Decode(&kvParis)
		replacement[s.Name] = kvParis
	}
	return replacement.ExpandAsText(text)
}

//NewSecret creates a secret
func NewSecret(target interface{}, resource *Resource) *Secret {
	secret := &Secret{Resource: resource}
	switch v := target.(type) {
	case []byte:
		secret.payload = v
	case string:
		secret.payload = []byte(v)
	default:
		secret.Target = target
	}
	return secret
}
