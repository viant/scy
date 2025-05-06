package cmd

import (
	"fmt"
	"github.com/viant/scy/cred"
	"os"
	"path"
	"strings"
)

type Options struct {
	Mode      string `short:"m" long:"mode" choice:"secure"  choice:"reveal" choice:"signJwt" choice:"verifyJwt" choice:"auth"`
	SourceURL string `short:"s" long:"src" description:"source location"`
	RSAKey    string `short:"r" long:"rsa" description:"private/public key location"`
	HMacKey   string `short:"a" long:"hmac" description:"hmac key location (base64 encoded)"`
	DestURL   string `short:"d" long:"dest" description:"dest location"`
	ExpirySec int    `short:"e" long:"expiry" description:"expiry TTL in sec"`
	Firebase  bool   `short:"f" long:"firebase" description:"firebase"`
	Target    string `short:"t" long:"target" default:"raw" choice:"raw" choice:"basic"  choice:"sha1" choice:"aws" choice:"ssh" choice:"generic"  choice:"jwt" choice:"oauth2" choice:"key" description:"target type"`
	Key       string `short:"k" long:"key" description:"key i.e blowfish://default"`
	ProjectId string `short:"p" long:"projectId" description:"project id"`
}

func (o *Options) Validate() error {
	tagetType, _ := cred.TargetType(o.Target)
	switch o.Mode {
	case "secure":
		if tagetType != nil && o.SourceURL == "" {
			switch o.Target {
			case "basic", "key":
			default:
				return fmt.Errorf("src was empty")
			}
		}
		if o.DestURL == "" {
			return fmt.Errorf("dst was empty")
		}
	case "reveal":
		if o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
	case "signJwt":
		if o.RSAKey == "" && o.HMacKey == "" {
			return fmt.Errorf("RSAKey/HMacKey were empty")
		}
		if o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
	case "verifyJwt":
		if o.Firebase {

		} else if o.RSAKey == "" && o.HMacKey == "" {
			return fmt.Errorf("RSAKey/HMacKey was empty")
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
	if location == "" {
		return ""
	}
	if strings.HasPrefix(location, "~") {
		return os.Getenv("HOME") + location[1:]
	}
	if !strings.Contains(location, ":/") && !strings.HasPrefix(location, "/") {
		cwd, _ := os.Getwd()
		return path.Join(cwd, location)
	}
	return location
}
