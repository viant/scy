package scy_test

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	"github.com/viant/scy/kms"
	_ "github.com/viant/scy/kms/blowfish"
	"github.com/viant/scy/kms/gcp"
	"log"
)

func ExampleService_Load() {

	{ //loading secret from google cloud secret manager

		resource := scy.NewResource("secret", "gcp://secretmanager/projects/gcp-e2e/secrets/test2sec", "")
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
		kms.Register(gcp.Schema, cipher)

		resource := scy.NewResource("secret", "gs://mybucket/asset.enc", "gcp://kms/projects/my-project/locations/us-central1/keyRings/my-ring/cryptoKeys/my-key")
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
		resource := scy.NewResource(cred.Basic{}, "/tmp/secret.json", "blowfish://default")
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
		resource := scy.NewResource("password", "/tmp/cred.enc", "blowfish://default")
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
