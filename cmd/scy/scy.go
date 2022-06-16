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
)

func main() {
	//cmd.Run([]string{
	//	"-m=secure",
	//	"-s=s1.json",
	//	"-d=gcp://secretmanager/projects/viant-e2e/secrets/aw1test",
	//	"-k=blowfish://default",
	//	"-t=sha1",
	//
	//	//"-m=reveal",
	//	//"-s=gcp://secretmanager/projects/viant-e2e/secrets/logger_rubicon",
	//	//"-k=blowfish://default",
	//	//"-t=sha1",
	//})
	cmd.Run(os.Args[1:])
}
