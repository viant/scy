package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"github.com/viant/toolbox"
)


// RevealCmd command for revealing secrets
type RevealCmd struct {
	TypedSource
	Key       string `short:"k" long:"key" description:"key i.e blowfish://default"`
}

// Init normalizes file locations
func (r *RevealCmd) Init() {
	r.SourceURL = normalizeLocation(r.SourceURL)
}

// Validate validates the reveal command options
func (r *RevealCmd) Validate() error {
	if r.SourceURL == "" {
		return fmt.Errorf("src was empty")
	}
	return nil
}

// Execute runs the reveal command
func (r *RevealCmd) Execute(args []string) error {
	r.Init()
	return Reveal(r)
}


// Reveal reveals secret
func Reveal(reveal *RevealCmd) error {
	secret, err := loadSecret(reveal)
	if err != nil {
		return err
	}
	if !secret.IsPlain && secret.Target != nil {
		aMap := map[string]interface{}{}
		toolbox.DefaultConverter.AssignConverted(&aMap, secret.Target)
		aMap = toolbox.DeleteEmptyKeys(aMap)
		if data, err := json.Marshal(aMap); err == nil {
			fmt.Println(string(data))
			return nil
		}
	}
	fmt.Println(secret.String())
	return nil
}

// loadSecret loads a secret from a source
func loadSecret(cmd interface{}) (*scy.Secret, error) {
	srv := scy.New()
	var target interface{} = nil

	var sourceURL, targetStr, keyStr string

	switch v := cmd.(type) {
	case *RevealCmd:
		sourceURL = v.SourceURL
		targetStr = v.Target
		keyStr = v.Key
	case *AuthCmd:
		sourceURL = v.SourceURL
		targetStr = v.Target
		keyStr = v.Key
	}

	targetType, err := cred.TargetType(targetStr)
	if err != nil {
		return nil, err
	}
	if targetType != nil {
		target = targetType
	}
	resource := scy.NewResource(target, sourceURL, keyStr)
	secret, err := srv.Load(context.Background(), resource)
	if err != nil {
		return nil, err
	}
	return secret, nil
}
