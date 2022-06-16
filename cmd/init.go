package cmd

import (
	"github.com/viant/afsc/gs"
	"github.com/viant/scy/auth/gcp"
	"github.com/viant/scy/auth/gcp/client"
	"google.golang.org/api/option"
	"os"
)

func init() {
	os.Setenv("AWS_SDK_LOAD_CONFIG", "true")
	auth := gcp.New(client.NewScy())
	gs.SetOptions(option.WithTokenSource(auth.TokenSource("https://www.googleapis.com/auth/devstorage.read_write")))
}
