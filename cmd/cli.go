package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/viant/afs"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"github.com/viant/toolbox"
	"golang.org/x/crypto/ssh/terminal"
	"log"
	"reflect"
	"syscall"
	"time"
)

func Run(args []string) {
	options := &Options{}
	_, err := flags.ParseArgs(options, args)
	if err != nil {
		log.Fatal(err)
	}
	if err := options.Validate(); err != nil {
		log.Fatal(err)
	}
	switch options.Mode {
	case "secure":
		err = Secure(options)
	case "reveal":
		err = Reveal(options)
	}
	if err != nil {
		log.Fatal(err)
	}
}

//Reveal reveals secret
func Reveal(options *Options) error {
	srv := scy.New()
	var target interface{} = nil
	if targetType := getTarget(options.Target); targetType != nil {
		target = targetType
	}
	resource := scy.NewResource(target, options.SourceURL, options.Key)
	secret, err := srv.Load(context.Background(), resource)
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

func getTarget(target string) reflect.Type {
	var result reflect.Type
	switch target {
	case "aws":
		result = reflect.TypeOf(cred.Generic{})
	case "basic":
		result = reflect.TypeOf(cred.Basic{})
	case "jwt":
		result = reflect.TypeOf(cred.JwtConfig{})
	case "sha1":
		result = reflect.TypeOf(cred.SHA1{})
	case "ssh":
		result = reflect.TypeOf(cred.SSH{})
	case "rsa":
		result = reflect.TypeOf(cred.RSA{})
	case "generic":
		result = reflect.TypeOf(cred.Generic{})
	}
	return result
}

//Secure secure secrets
func Secure(options *Options) error {
	data, err := readSource(options)
	if err != nil {
		log.Fatal(err)
	}
	resource := scy.NewResource(getTarget(options.Target), options.DestURL, options.Key)
	var secret *scy.Secret
	if target := getTarget(options.Target); target != nil {
		instance := reflect.New(target).Interface()
		if err := json.Unmarshal(data, instance); err != nil {
			return err
		}
		secret = scy.NewSecret(instance, resource)
	} else {
		secret = scy.NewSecret(string(data), resource)
	}
	srv := scy.New()
	return srv.Store(context.Background(), secret)
}

func readSource(options *Options) ([]byte, error) {
	if options.SourceURL != "" {
		fs := afs.New()
		return fs.DownloadWithURL(context.Background(), options.SourceURL)
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
		rawSecret, err = terminal.ReadPassword(syscall.Stdin)
		if err != nil {
			err = fmt.Errorf("failed to read secret %v", err)
			return
		}
		fmt.Print("\nRetype Secret: ")
		rawSecret2, err = terminal.ReadPassword(syscall.Stdin)
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
