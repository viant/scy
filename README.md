## scy - secure store api for golang

[![GoReportCard](https://goreportcard.com/badge/github.com/viant/scy)](https://goreportcard.com/report/github.com/viant/scy)
[![GoDoc](https://godoc.org/github.com/viant/scy?status.svg)](https://godoc.org/github.com/viant/scy)

This library is compatible with Go 1.16+

Please refer to [`CHANGELOG.md`](CHANGELOG.md) if you encounter breaking changes.


- [Motivation](#motivation)
- [Introduction](#introduction)
- [Usage](#usage) 
- [License](#license)
- [Credits and Acknowledgements](#credits-and-acknowledgements)



## Motivation

The goal of this project is provide API for integrating secret.

## Usage


```go
package mypkg

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"github.com/viant/scy/kms/gcp"
	_ "github.com/viant/scy/kms/blowfish"
	_ "github.com/viant/afsc/tree/master/gcp/secretmanager"
	"log"
)

func ExampleService_Load() {


	{ //loading secret from google cloud secret manager
		resource := scy.NewResource("secret", 
			"gcp://secretmanager/projects/gcp-e2e/secrets/myseret", "")
		secrets := scy.New()
		secret, err := secrets.Load(context.Background(), resource)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%v %v\n", secret.String())
	}

	{ //loading secret from cloud storage encrypted with GCP KMS

		cipher, err := gcp.New(context.Background())
		if err != nil {
			log.Fatalln(err)
		}
		kms.Register(gcp.Scheme, cipher)
		
		resource := scy.NewResource("secret", 
			"gs://mybucket/asset.enc", 
			"gcp://kms/projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key")
		secrets := scy.New()
		secret, err := secrets.Load(context.Background(), resource)
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%v %v\n", secret.String())
	}


	{ //loading local secret
		//Assume that : /tmp/secret.json {"Username":"Bob","EncryptedPassword":"AAAAAAAAAAAtM4MTWOJOJ4SyE44PjH66"}
		//make sure _ "github.com/viant/scy/kms/blowfish" is imported
		resource := scy.NewResource(cred.Basic{}, 
		    "/tmp/secret.json", 
		    "blowfish://default")
		secrets := scy.New()
		secret, err := secrets.Load(context.Background(), resource)
		if err != nil {
			log.Fatalln(err)
		}
		basicCred := secret.Target.(*cred.Basic)
		fmt.Printf("user: %v, password: %v\n", basicCred.Username, basicCred.Password)
		dsn := "${cred.Username}:${cred.Password}}@/dbname"
		db, err := sql.Open("mysql", secret.Expand(dsn))
		fmt.Printf("%v %v\n", db, err)
	}

	{ //loading encrypted file
		resource := scy.NewResource("password", "/tmp/password.enc", "blowfish://default")
		secrets := scy.New()
		secret, err := secrets.Load(context.Background(), resource)
		if err != nil {
			log.Fatalln(err)
		}

		dsn := "myuser:${password}}@/dbname"
		db, err := sql.Open("mysql", secret.Expand(dsn))
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%v %v\n", db, err)
	}

	{ //loading structured encrypted file
		resource := scy.NewResource("cred", "/tmp/cred.enc", "blowfish://default")
		secrets := scy.New()
		secret, err := secrets.Load(context.Background(), resource)
		if err != nil {
			log.Fatalln(err)
		}
		dsn := "${cred.Username}:${cred.Password}}@/dbname"
		db, err := sql.Open("mysql", secret.Expand(dsn))
		if err != nil {
			log.Fatalln(err)
		}
		fmt.Printf("%v %v\n", db, err)
	}

	
}


```

## Secret store file system

You can use diractly the following [Secret stores](https://github.com/viant/afsc#secret-stores)
 - GCP Google Secret Manager
 - AWS - Secret Manager
 - AWS - System Manager - Parameter

## Keys

- gcp://kms/projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key
- blowfish://default
- blowfish://env/mykey
- blowfish://localhost/localpath



## Contribution


scy is an open source project and contributors are welcome!

See [TODO](TODO.md) list


## License

The source code is made available under the terms of the Apache License, Version 2, as stated in the file `LICENSE`.

Individual files may be made available under their own specific license,
all compatible with Apache License, Version 2. Please see individual files for details.

## Credits and Acknowledgements

Authors:

- Adrian Witas
