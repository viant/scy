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
	"github.com/viant/scy/auth/firebase"
	"github.com/viant/scy/auth/gcp"
	"github.com/viant/scy/auth/gcp/client"
	"github.com/viant/scy/auth/jwt/signer"
	"github.com/viant/scy/auth/jwt/verifier"
	"github.com/viant/scy/cred"
	"github.com/viant/toolbox"
	"golang.org/x/crypto/ssh/terminal"
	"google.golang.org/api/option"
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
	options.Init()
	if err := options.Validate(); err != nil {
		log.Fatal(err)
	}
	switch options.Mode {
	case "secure":
		err = Secure(options)
	case "reveal":
		err = Reveal(options)
	case "signJwt":
		err = SignJwtClaim(options)
	case "verifyJwt":
		err = VerifyJwtClaim(options)
	case "auth":
		err = Auth(options)

	}
	if err != nil {
		log.Fatal(err)
	}
}

func Auth(options *Options) error {
	if options.Firebase {
		return AuthFirebase(options)
	}
	return fmt.Errorf("unsupported auth mode")
}

func AuthFirebase(options *Options) error {
	options.Target = "basic"
	secret, err := loadSecret(options)
	if err != nil {
		return err
	}
	gcpService := gcp.New(client.NewScy())
	tokenSource := gcpService.TokenSource("https://www.googleapis.com/auth/cloud-platform")
	identity, err := firebase.New(context.Background(), nil, option.WithTokenSource(tokenSource))
	if err != nil {
		return err
	}
	basicCred := secret.Target.(*cred.Basic)
	token, err := identity.InitiateBasicAuth(context.Background(), basicCred.Username, basicCred.Password)
	if err != nil {
		return err
	}
	data, err := json.Marshal(token)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", data)
	return nil
}

func VerifyJwtClaim(options *Options) error {
	jwtverifier := verifier.New(&verifier.Config{RSA: &scy.Resource{
		URL: options.RSAKey,
		Key: options.Key,
	}, HMAC: &scy.Resource{
		URL: options.HMacKey,
		Key: options.Key,
	}})

	if err := jwtverifier.Init(context.Background()); err != nil {
		return err
	}
	fs := afs.New()
	jwtTokenString, err := fs.DownloadWithURL(context.Background(), options.SourceURL)
	if err != nil {
		return err
	}
	jwtClaim, err := jwtverifier.VerifyClaims(context.Background(), string(jwtTokenString))
	if err != nil {
		return err
	}
	data, _ := json.Marshal(jwtClaim)
	fmt.Printf("JWT CLAIM: %s\n", data)
	return nil
}

func SignJwtClaim(options *Options) error {

	cfg := &signer.Config{}
	if options.HMacKey != "" {
		cfg.HMAC = &scy.Resource{
			URL: options.HMacKey,
			Key: options.Key,
		}
	} else if options.RSAKey != "" {
		cfg.RSA = &scy.Resource{
			URL: options.RSAKey,
			Key: options.Key,
		}
	}
	jwtSigner := signer.New(cfg)
	if err := jwtSigner.Init(context.Background()); err != nil {
		return err
	}
	fs := afs.New()
	var content = map[string]interface{}{}
	data, err := fs.DownloadWithURL(context.Background(), options.SourceURL)
	if err != nil {
		return err
	}
	if err = json.Unmarshal(data, &content); err != nil {
		return fmt.Errorf("invalid JSON content: %v", err)
	}
	expiry := time.Duration(options.ExpirySec) * time.Second
	if expiry == 0 {
		expiry = time.Hour
	}
	token, err := jwtSigner.Create(expiry, content)
	if err != nil {
		return err
	}
	fmt.Printf("JWT TOKEN: %s\n", token)
	return nil
}

// Reveal reveals secret
func Reveal(options *Options) error {
	secret, err := loadSecret(options)
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

func loadSecret(options *Options) (*scy.Secret, error) {
	srv := scy.New()
	var target interface{} = nil
	targetType, err := cred.TargetType(options.Target)
	if err != nil {
		return nil, err
	}
	if targetType != nil {
		target = targetType
	}
	resource := scy.NewResource(target, options.SourceURL, options.Key)
	secret, err := srv.Load(context.Background(), resource)
	if err != nil {
		return nil, err
	}
	return secret, nil
}

// Secure secure secrets
func Secure(options *Options) error {
	data, err := readSource(options)
	if err != nil {
		log.Fatal(err)
	}
	targetType, err := cred.TargetType(options.Target)
	if err != nil {
		return err
	}
	var target reflect.Type
	if targetType != nil {
		target = targetType
	}
	resource := scy.NewResource(target, options.DestURL, options.Key)
	var secret *scy.Secret
	if target != nil {
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
