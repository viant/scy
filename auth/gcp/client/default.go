package client

import (
	_ "embed"
	_ "github.com/viant/scy/kms/blowfish"

	"context"
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/gcp"
)

var (
	//go:embed gcloud.enc
	gcloudEnc []byte
	//go:embed scy.enc
	scyEnc []byte
)

var sdkClient *gcp.Client

//NewGCloud return Google Cloud SDK Client
func NewGCloud() *gcp.Client {
	if sdkClient != nil {
		return sdkClient
	}
	sdkClient, _ = loadEncryptedClient(gcloudEnc)
	return sdkClient
}

var scyClient *gcp.Client

//NewScy return Scy Client
func NewScy() *gcp.Client {
	if scyClient != nil {
		return scyClient
	}
	var err error
	scyClient, err = loadEncryptedClient(scyEnc)
	fmt.Printf("%v\n", err)
	return scyClient
}

func loadEncryptedClient(enc []byte) (*gcp.Client, error) {
	scyService := scy.New()
	resource := scy.NewResource(gcp.Client{}, "", "blowfish://default")
	resource.Data = enc
	secret, err := scyService.Load(context.Background(), resource)
	if err != nil {
		return nil, err
	}
	result, ok := secret.Target.(*gcp.Client)
	if !ok {
		return nil, fmt.Errorf("expected: %T, but had: %T", result, secret.Target)
	}
	return result, nil
}
