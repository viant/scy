## Scy secure secret store CLI client


#### Installation

Latest binary can be found in [release](https://github.com/viant/scy/releases) section


On x64 OSX

```bash
wget https://github.com/viant/scy/releases/download/v0.1.0/scy_darwin_x64.tar.gz
tar xvzf scy_darwin_x64.tar.gz
cp scy /usr/local/bin
```

On x64 Linux

```bash
wget https://github.com/viant/scy/releases/download/v0.1.0/scy_linux_x64.tar.gz
tar xvzf scy_darwin_x64.tar.gz
cp scy /usr/local/bin
```


#### Usage

```bash
./scy -h
```

You can use any afs supported storage, also including the following secret store managers:

- [GCP Google Secret Manager](https://github.com/viant/afsc/tree/master/gcp/secretmanager)
    i.e ` "gcp://secretmanager/projects/my-project/secrets/my_secret" `
- [AWS - Secret Manager](https://github.com/viant/afsc/tree/master/aws/secretmanager)
    i.e `aws://secretmanager/us-west-1/secret/prod/my/mysecret1`
- [AWS - System Manager - Parameter](https://github.com/viant/afsc/tree/master/aws/ssm)
  i.e `aws://ssm/us-west-1/parameter/myParamX`


To use AWS make the following files are present

```bash
~/.aws/config
[default]
region = us-west-1

~/.aws/credentials
[default]
aws_access_key_id = KEY HERE
aws_secret_access_key = SECRET HERE
```

To use GCP auth 

```json
export GOOGLE_APPLICATION_CREDENTIALS=myGoogle.secret
```

##### Securing secrets

### Text

```bash
scy -m=secure  -d=gcp://secretmanager/projects/viant-e2e/secrets/my_raw_secret1  -k=blowfish://default -t=raw ```
```

### Basic credential

The source and dest can by any file system including local FS.

```bash
./scy -m=secure -s=unsecure_cred.json -d=securet_cred.json  -k=blowfish://default -t=basic
```


### SHA1

```bash
scy -m=secure -s=mySHA1.json -d=gcp://secretmanager/projects/myProject/secrets/my_secret1  -k=blowfish://default -t=sha1
```

where mySHA1.json uses the following format

```json
{"IntegrityKey":"base64encodedIntegrityKey","Key":"base64encodedKey"}
```


##### Revealing secrets

### Text

```bash
scy -m=reveal -s=gcp://secretmanager/projects/viant-e2e/secrets/aw1test  -k=blowfish://default -t=ra
```

### Basic credential

The source and dest can by any file system including local FS.

```bash
./scy -m=reveal  -s=securet_cred.json  -k=blowfish://default -t=basic
```

### SHA1

```bash
scy -m=reveal -s=gcp://secretmanager/projects/myProject/secrets/my_secret1  -k=blowfish://default -t=sha1
```

