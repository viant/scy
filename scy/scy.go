package main

import (
	_ "github.com/viant/afsc/aws"
	_ "github.com/viant/afsc/gcp"
	_ "github.com/viant/afsc/gs"
	_ "github.com/viant/afsc/s3"
	"github.com/viant/scy/cmd"
	_ "github.com/viant/scy/kms/blowfish"
	_ "github.com/viant/scy/kms/gcp"
	"os"
	//"os"
)

// Version is injected at build time via -ldflags "-X 'main.Version=...".
// It defaults to an empty string when not set.
var Version string

func main() {
	cmd.RunWithCommands(os.Args[1:])
}
