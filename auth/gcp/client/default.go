package client

import (
	"context"
	_ "embed"
	"fmt"
	"github.com/viant/scy"
	_ "github.com/viant/scy/kms/blowfish"
	"golang.org/x/oauth2"
)

var (
	//go:embed gcloud.enc
	gcloudEnc []byte
	//go:embed scy.enc
	scyEnc []byte
)

var sdkClient *oauth2.Config

// NewGCloud return Google Cloud SDK Client
func NewGCloud() *oauth2.Config {
	if sdkClient != nil {
		return sdkClient
	}
	var temp = make([]byte, len(gcloudEnc))
	copy(temp, gcloudEnc)
	sdkClient, _ = loadEncryptedClient(temp)
	return sdkClient
}

var scyClient *oauth2.Config

// NewScy return Scy Client
func NewScy() *oauth2.Config {
	if scyClient != nil {
		return scyClient
	}
	var temp = make([]byte, len(scyEnc))
	copy(temp, scyEnc)
	scyClient, _ = loadEncryptedClient(temp)
	return scyClient
}

func loadEncryptedClient(enc []byte) (*oauth2.Config, error) {
	scyService := scy.New()
	resource := scy.NewResource(oauth2.Config{}, "", "blowfish://default")
	resource.Data = enc
	secret, err := scyService.Load(context.Background(), resource)
	if err != nil {
		return nil, err
	}
	result, ok := secret.Target.(*oauth2.Config)
	if !ok {
		return nil, fmt.Errorf("expected: %T, but had: %T", result, secret.Target)
	}
	return result, nil
}
