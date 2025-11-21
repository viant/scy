package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/viant/afs"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"github.com/viant/scy/cred/secret/term"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"os"
	"reflect"
	"time"
)

type SecureCmd struct {
	TypedSource
	DestURL string `short:"d" long:"dest" description:"dest location"`
	Key     string `short:"k" long:"key" description:"key i.e blowfish://default"`
}

// Execute runs the secure command
func (s *SecureCmd) Execute(args []string) error {
	s.Init()
	return Secure(s)
}

// SecureCmd command for securing secrets

// Init normalizes file locations
func (s *SecureCmd) Init() {
	s.SourceURL = normalizeLocation(s.SourceURL)
	s.DestURL = normalizeLocation(s.DestURL)
}

// Validate validates the secure command options
func (s *SecureCmd) Validate() error {
	targetType, _ := cred.TargetType(s.Target)
	if targetType != nil && s.SourceURL == "" {
		switch s.Target {
		case "basic", "key":
		default:
			return fmt.Errorf("src was empty")
		}
	}
	if s.DestURL == "" {
		return fmt.Errorf("dst was empty")
	}
	return nil
}

// Secure secures secrets
func Secure(secure *SecureCmd) error {
	data, err := readSource(secure)
	if err != nil {
		log.Fatal(err)
	}
	targetType, err := cred.TargetType(secure.Target)
	if err != nil {
		return err
	}
	var target reflect.Type
	if targetType != nil {
		target = targetType
	}
	srv := scy.New()

	resource := scy.NewResource(target, secure.DestURL, secure.Key)
	var secret *scy.Secret
	if target != nil {
		instance := reflect.New(target).Interface()
		if err := json.Unmarshal(data, instance); err != nil {
			return err
		}
		switch actual := instance.(type) {
		case *cred.SecretKey:
			if actual.EncryptedSecret != "" && actual.Secret == "" {
				if secret, err := srv.Load(context.Background(), scy.NewResource(target, secure.SourceURL, secure.Key)); err == nil {
					instance = secret.Target.(*cred.SecretKey)
				}
			}
		case *cred.Basic:
			if actual.EncryptedPassword != "" && actual.Password == "" {
				if secret, err := srv.Load(context.Background(), scy.NewResource(target, secure.SourceURL, secure.Key)); err == nil {
					instance = secret.Target.(*cred.Basic)
				}
			}
		case *cred.Generic:
			if actual.EncryptedPassword != "" && actual.Password == "" {
				if secret, err := srv.Load(context.Background(), scy.NewResource(target, secure.SourceURL, secure.Key)); err == nil {
					instance = secret.Target.(*cred.Generic)
				}
			}
		}
		secret = scy.NewSecret(instance, resource)
	} else {
		secret = scy.NewSecret(string(data), resource)
	}
	return srv.Store(context.Background(), secret)
}

// readSource reads source data
func readSource(cmd interface{}) ([]byte, error) {
	var sourceURL, targetStr, keyStr string

	switch v := cmd.(type) {
	case *SecureCmd:
		sourceURL = v.SourceURL
		targetStr = v.Target
		keyStr = v.Key
	}

	if sourceURL != "" {
		fs := afs.New()
		return fs.DownloadWithURL(context.Background(), sourceURL)
	}
	switch targetStr {
	case "basic":
		if keyStr == "" {
			keyStr = "blowfish://default"
		}
		user, password, err := term.ReadUserAndPassword(2 * time.Minute)
		if err != nil {
			return nil, err
		}
		basic := cred.Basic{Username: user, Password: password}
		return json.Marshal(basic)
	case "key":
		if keyStr == "" {
			keyStr = "blowfish://default"
		}

		keyId, keySecret, err := term.ReadSecretKey(2 * time.Minute)
		if err != nil {
			return nil, err
		}
		key := cred.SecretKey{Key: keyId, Secret: keySecret}
		return json.Marshal(key)
	}
	return readSecret(time.Minute)
}

func readSecret(timeout time.Duration) ([]byte, error) {
	completed := make(chan bool)
	var err error
	var rawSecret, rawSecret2 []byte
	var reader = func() {
		defer func() {
			completed <- true
		}()

		fmt.Print("Enter Secret: ")
		rawSecret, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			err = fmt.Errorf("failed to read secret %v", err)
			return
		}
		fmt.Print("\nRetype Secret: ")
		rawSecret2, err = terminal.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			err = fmt.Errorf("failed to read secret %v", err)
			return
		}
		if !bytes.Equal(rawSecret, rawSecret2) {
			err = errors.New("secret did not match")
		}
	}
	go reader()
	select {
	case <-completed:
	case <-time.After(timeout):
		err = fmt.Errorf("reading secret timeout")
	}
	return rawSecret, nil
}
