package flow

type Options struct {
	scopes        []string
	authURLParams map[string]string
	postParams    map[string]string
	state         string
	codeVerifier  string
	usePKCE       bool
}



func (o *Options) Scopes(scopes ...string) []string {
	var dedupeScopes []string
	var uniques = map[string]bool{}
	scopes = append(o.scopes, scopes...)
	for _, scope := range scopes {
		if _, ok := uniques[scope]; !ok {
			uniques[scope] = true
			dedupeScopes = append(dedupeScopes, scope)
		}
	}
	return dedupeScopes
}


func (o *Options) State() string {
	if o.state != "" {
		return o.state
	}
	o.state = randomToken()
	return o.state
}

func (o *Options) CodeVerifier() (string, error) {
	if o.codeVerifier != "" {
		return o.codeVerifier, nil
	}
	o.codeVerifier = randomToken()
	return o.codeVerifier, nil
}

func NewOptions(opts []Option) *Options {
	ret := &Options{
		scopes:        []string{},
		authURLParams: make(map[string]string),
		postParams:    make(map[string]string),
	}
	for _, opt := range opts {
		opt(ret)
	}
	return ret
}

type Option func(*Options)

func WithScopes(scopes ...string) Option {
	return func(o *Options) {
		o.scopes = append(o.scopes, scopes...)
	}
}
func WithAuthURLParam(key string, value string) Option {
	return func(o *Options) {
		o.authURLParams[key] = value
	}
}

func WithPostParam(key string, value string) Option {
	return func(o *Options) {
		o.postParams[key] = value
	}
}

func WithPostParams(values map[string]string) Option {
	return func(o *Options) {
		for k, v := range values {
			o.postParams[k] = v
		}
	}
}

func WithState(state string) Option {
	return func(o *Options) {
		o.state = state
	}
}

// WithPKCE enables or disables PKCE flow
func WithPKCE(enabled bool) Option {
	return func(o *Options) {
		o.usePKCE = enabled
	}
}
