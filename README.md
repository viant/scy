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
    src := scy.New()
    //let assume secret is stored as {"username": "blath", "passwrod":"rere"}
    secret, err := src.Load(ctx, NewResource( "cred", "gcp://secretmanager/projects/gcp-e2e/secrets/test_cred", "")
    dsn = "${cred.Username}:${cred.Password}}@/dbname"
    db, err := sql.Open("mysql", secret.Expand(dsn))
    
    //let assume secret is stored as "my_encrupted_password"
    secret, err := src.Load(ctx, NewResource("password", "gcp://secretmanager/projects/gcp-e2e/secrets/test_password", ""))
    dsn =  "myuser:${password}}@/dbname"
    db, err := sql.Open("mysql", secret.Expand(dsn))


    //let assume secret is stored as BasicAuth JSON
    secret, err := src.Load(ctx, NewResource(&cred.BasicAuth{}, "gcp://secretmanager/projects/gcp-e2e/secrets/test2sec", "blowfish://default")
    basicAtuth := secret.Target.(*cred.BasicAuth)
    dsn = basicAtuth.Username":" +basicAtuth.Password+ "@/dbname"
    db, err := sql.Open("mysql", secret.Expand(dsn))

```

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
