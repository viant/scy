package client

import (
	_ "embed"
	"github.com/viant/scy/auth/client"
	_ "github.com/viant/scy/kms/blowfish"
	"golang.org/x/oauth2/google"

	"context"
	"fmt"
	"github.com/viant/scy"
)

var (
	//go:embed gcloud.enc
	gcloudEnc []byte
	//go:embed scy.enc
	scyEnc []byte
)

var sdkClient *client.Client

// NewGCloud return Google Cloud SDK Client
func NewGCloud() *client.Client {
	if sdkClient != nil {
		return sdkClient
	}
	var temp = make([]byte, len(gcloudEnc))
	copy(temp, gcloudEnc)
	sdkClient, _ = loadEncryptedClient(temp)
	sdkClient.Endpoint = google.Endpoint
	return sdkClient
}

var scyClient *client.Client

// NewScy return Scy Client
func NewScy() *client.Client {
	if scyClient != nil {
		return scyClient
	}
	var temp = make([]byte, len(scyEnc))
	copy(temp, scyEnc)
	scyClient, _ = loadEncryptedClient(temp)
	scyClient.Endpoint = google.Endpoint
	return scyClient
}

func loadEncryptedClient(enc []byte) (*client.Client, error) {
	scyService := scy.New()
	resource := scy.NewResource(client.Client{}, "", "blowfish://default")
	resource.Data = enc
	secret, err := scyService.Load(context.Background(), resource)
	if err != nil {
		return nil, err
	}
	result, ok := secret.Target.(*client.Client)
	if !ok {
		return nil, fmt.Errorf("expected: %T, but had: %T", result, secret.Target)
	}

	return result, nil
}
