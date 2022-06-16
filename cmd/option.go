package cmd

import (
	"fmt"
)

type Options struct {
	Mode      string `short:"m" long:"mode" choice:"secure"  choice:"reveal"`
	SourceURL string `short:"s" long:"src" description:"source location"`
	DestURL   string `short:"d" long:"dest" description:"dest location"`
	Target    string `short:"t" long:"target" default:"raw" choice:"raw" choice:"basic"  choice:"sha1" choice:"aws" choice:"ssh" choice:"generic" choice:"jwt"`
	Key       string `short:"k" long:"key" description:"key i.e blowfish://default"`
}

func (o *Options) Validate() error {
	switch o.Mode {
	case "secure":
		if getTarget(o.Target) != nil && o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
		if o.DestURL == "" {
			return fmt.Errorf("dst was empty")
		}
	case "reveal":
		if o.SourceURL == "" {
			return fmt.Errorf("src was empty")
		}
	case "":
		return fmt.Errorf("mode was empty")
	}
	return nil
}
