package cmd

type TypedSource struct {
	SourceURL string `short:"s" long:"src" description:"source location"`
	Target    string `short:"t" long:"target" default:"raw" choice:"raw" choice:"basic"  choice:"sha1" choice:"aws" choice:"ssh" choice:"generic"  choice:"jwt" choice:"oauth2" choice:"key" description:"target type"`
}

// Options is the main command structure with command annotations
type Options struct {
	Secure    *SecureCmd     `command:"secure" description:"secures secrets"`
	Reveal    *RevealCmd     `command:"reveal" description:"reveals secrets"`
	SignJwt   *SignJwtCmd    `command:"signJwt" description:"sign JWT"`
	VerifyJwt *VerifyJwtCmd  `command:"verifyJwt" description:"verify JWT"`
	Authorize *AuthorizeCmd  `command:"authorize" description:"authorize using OAuth2"`
}

// Init normalizes file locations
func (options *Options) Init(args string) {
	switch args {
	case "reveal":
		options.Reveal = &RevealCmd{}
		options.Reveal.Init()
	case "secure":
		options.Secure = &SecureCmd{}
		options.Secure.Init()
	case "verifyJwt":
		options.VerifyJwt = &VerifyJwtCmd{}
		options.VerifyJwt.Init()
	case "signJwt":
		options.SignJwt = &SignJwtCmd{}
		options.SignJwt.Init()
	case "authorize":
		options.Authorize = &AuthorizeCmd{}
		options.Authorize.Init()
	}
}
