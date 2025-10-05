## Scy secure secret store CLI client


### Installation

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
scy -h
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

#### Securing (creating) secrets

Notes:
- `-d/--dest` is any afs URL (local path, GCP Secret Manager, AWS Secret Manager/SSM, etc.).
- `-k/--key` is the KMS key reference (e.g., `blowfish://default`, `gcp://kms/...`).
- `-s/--src` can point to a JSON file with the target payload. For `raw`, `basic`, and `key`, you can omit `-s` to be prompted interactively.

##### Raw (text)

Interactive entry (prompts twice):
```bash
scy secure -d=gcp://secretmanager/projects/viant-e2e/secrets/my_raw_secret1 -k=blowfish://default -t=raw
```

From file:
```bash
scy secure -s=./mysecret.txt -d=gcp://secretmanager/projects/acme/secrets/raw1 -k=blowfish://default -t=raw
```

##### Key (env key/value)

Interactive entry for key id and secret:
```bash
scy secure -d=./secret_key.json -k=blowfish://default -t=key
```

From file (`secret_key.json`):
```json
{"Key":"MY_API_KEY","Secret":"super-secret"}
```
```bash
scy secure -s=secret_key.json -d=gcp://secretmanager/projects/acme/secrets/api_key -k=blowfish://default -t=key
```

##### Basic credential

Interactive entry for username/password:
```bash
scy secure -d=./basic.json -k=blowfish://default -t=basic
```

From file (`unsecure_cred.json`):
```json
{"Username":"alice","Password":"p@ssw0rd","Email":"alice@example.com"}
```
```bash
scy secure -s=unsecure_cred.json -d=secure_cred.json -k=blowfish://default -t=basic
```

##### SHA1

From file (`mySHA1.json`):
```json
{"IntegrityKey":"base64encodedIntegrityKey","Key":"base64encodedKey"}
```
```bash
scy secure -s=mySHA1.json -d=gcp://secretmanager/projects/myProject/secrets/my_secret1 -k=blowfish://default -t=sha1
```

##### SSH

From file (`ssh.json`):
```json
{
  "Username": "ubuntu",
  "Password": "",
  "PrivateKeyPath": "~/.ssh/id_rsa",
  "PrivateKeyPassword": "optional-passphrase"
}
```
```bash
scy secure -s=ssh.json -d=gcp://secretmanager/projects/acme/secrets/ssh1 -k=blowfish://default -t=ssh
```

You can also inline a private key payload (PEM) as `PrivateKeyPayload` instead of `PrivateKeyPath`.

##### AWS

From file (`aws.json`):
```json
{
  "Id": "aws-user-id",
  "Region": "us-west-1",
  "Endpoint": "",
  "Session": {"RoleArn":"arn:aws:iam::123456789012:role/MyRole","Name":"my-session"},
  "Key": "AWS_ACCESS_KEY_ID",
  "Secret": "AWS_SECRET_ACCESS_KEY"
}
```
```bash
scy secure -s=aws.json -d=aws://secretmanager/us-west-1/secret/prod/my/app -k=blowfish://default -t=aws
```

##### Generic

Generic can hold Basic, SecretKey, SSH, or JWT fields. Example with basic-style fields (`generic.json`):
```json
{"Username":"svcuser","Password":"svcpass"}
```
```bash
scy secure -s=generic.json -d=gcp://secretmanager/projects/acme/secrets/generic1 -k=blowfish://default -t=generic
```

##### JWT config

From file (`jwt.json`):
```json
{
  "client_email": "svc@project.iam.gserviceaccount.com",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
  "private_key_id": "abcd1234",
  "token_url": "https://oauth2.googleapis.com/token"
}
```
```bash
scy secure -s=jwt.json -d=gcp://secretmanager/projects/acme/secrets/jwtcfg -k=blowfish://default -t=jwt
```

##### OAuth2 config

From file (`oauth2.json`):
```json
{
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "redirect_url": "http://localhost/callback",
  "endpoint": {"auth_url":"https://provider/authorize","token_url":"https://provider/token"}
}
```
```bash
scy secure -s=oauth2.json -d=gcp://secretmanager/projects/acme/secrets/oauth2cfg -k=blowfish://default -t=oauth2
```


#### Revealing secrets

Prints decrypted value or JSON (when structured):

```bash
# Raw
scy reveal -s=gcp://secretmanager/projects/viant-e2e/secrets/my_raw_secret1 -k=blowfish://default -t=raw

# Key
scy reveal -s=./secret_key.json -k=blowfish://default -t=key

# Basic
scy reveal -s=secure_cred.json -k=blowfish://default -t=basic

# SHA1
scy reveal -s=gcp://secretmanager/projects/myProject/secrets/my_secret1 -k=blowfish://default -t=sha1

# SSH
scy reveal -s=gcp://secretmanager/projects/acme/secrets/ssh1 -k=blowfish://default -t=ssh

# AWS
scy reveal -s=aws://secretmanager/us-west-1/secret/prod/my/app -k=blowfish://default -t=aws

# Generic
scy reveal -s=gcp://secretmanager/projects/acme/secrets/generic1 -k=blowfish://default -t=generic

# JWT config
scy reveal -s=gcp://secretmanager/projects/acme/secrets/jwtcfg -k=blowfish://default -t=jwt

# OAuth2 config
scy reveal -s=gcp://secretmanager/projects/acme/secrets/oauth2cfg -k=blowfish://default -t=oauth2
```


#### JWT helpers

- Sign claims (from JSON file):
```bash
echo '{"user_id":123,"email":"dev@viantinc.com"}' > claims.json
scy signJwt -s=claims.json -r=./private.scy -k=blowfish://default -e=3600
```

- Verify token:
```bash
scy verifyJwt -s=./token.txt -r=./public.scy -k=blowfish://default
```

- Verify Firebase token:
```bash
scy verifyJwt -s=./token.txt --firebase -p=my-gcp-project
```

#### OAuth2 authorization

Start an OAuth2 flow using a stored config and basic creds:
```bash
scy authorize -a=Browser \
  -c=gcp://secretmanager/projects/acme/secrets/oauth2cfg|blowfish://default \
  -e=gcp://secretmanager/projects/acme/secrets/basic.json|blowfish://default \
  -s=https://www.googleapis.com/auth/cloud-platform \
  --usePKCE
```
