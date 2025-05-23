package firebase

import (
	firebase "firebase.google.com/go/v4"
	"github.com/viant/scy"
)

// Config represents firebase config
type Config struct {
	*firebase.Config
	Secrets   *scy.Resource
	WebAPIKey *scy.Resource
}
