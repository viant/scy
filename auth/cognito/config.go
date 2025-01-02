package cognito

import (
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
)

type Config struct {
	Client   *cred.Aws
	Resource *scy.Resource
	AuthFlow string
}

func (c *Config) Init() {
	if c.AuthFlow == "" {
		c.AuthFlow = "USER_PASSWORD_AUTH"
	}
}

func (c *Config) Validate() error {
	if c.Client == nil {
		return fmt.Errorf("client was empty")
	}
	return nil
}
