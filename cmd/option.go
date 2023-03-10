package cmd

import (
	"fmt"
	"github.com/viant/scy/cred"
	"os"
	"path"
	"strings"
)

type Options struct {
	Mode      string `short:"m" long:"mode" choice:"secure"  choice:"reveal" choice:"signJwt" choice:"verifyJwt"`
	SourceURL string `short:"s" long:"src" description:"source location"`
	RSAKey    string `short:"r" long:"rsa" description:"private/public key location"`
	DestURL   string `short:"d" long:"dest" description:"dest location"`
	ExpirySec int    `short:"e" long:"expiry" description:"expiry TTL in sec"`

	Target string `short:"t" long:"target" default:"raw" choice:"raw" choice:"basic"  choice:"sha1" choice:"aws" choice:"ssh" choice:"generic" choice:"jwt"`
	Key    string `short:"k" long:"key" description:"key i.e blowfish://default"`
}

func (o *Options) Validate() error {
	tagetType, _ := cred.TargetType(o.Target)
	switch o.Mode {
	case "secure":
		if tagetType != nil && o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
		if o.DestURL == "" {
			return fmt.Errorf("dst was empty")
		}
	case "reveal":
		if o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
	case "signJwt":
		if o.RSAKey == "" {
			return fmt.Errorf("RSAKey was empty")
		}
		if o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
	case "verifyJwt":
		if o.RSAKey == "" {
			return fmt.Errorf("RSAKey was empty")
		}
		if o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
	case "":
		return fmt.Errorf("mode was empty")
	}
	return nil
}

func (o *Options) Init() {
	o.SourceURL = normalizeLocation(o.SourceURL)
	o.DestURL = normalizeLocation(o.DestURL)
}

func normalizeLocation(location string) string {
	if strings.HasPrefix(location, "~") {
		return os.Getenv("HOME") + location[1:]
	}
	if !strings.Contains(location, ":/") && !strings.HasPrefix(location, "/") {
		cwd, _ := os.Getwd()
		return path.Join(cwd, location)
	}
	return location
}
