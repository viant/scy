## Secret service ##

Secret service provide convenient way of handling credentials.


## Generic Credentials retrieval

Service supports the following form of * to retrieve credentials:

1. URL i.e. mem://secret/localhost.json, secretmanager://....., 
2. Relative path i.e. localhost.json, in this case based directory will be used to lookup credential resource
3. Short name  i.e. localhost, in this case based directory will be used to lookup credential resource and .json ext will be added.


**Base directory** can be file or URL, if empty '$HOME/.secret/' is used 


```go

    service := secret.New() 
    var secret = secret.Resource("localhost")
	secret, err := service.Lookup(secret)
	if err !=nil {
		panic(err)
    }
    cred, ok := secret.Target.(*cred.Generic)
	if ! ok  {
	    panic("invalid secret type")
	}
```

Secrets are defined as `type Secrets map[secret.Key]secret.Resource`


## Secret expansion

Very common case for the application it to take encrypted credential to used wither username or password.
For example while running terminal command we may need to provide super user password and sometimes other secret, 
in one command that we do not want to reveal to final user.


Take the following code as example:

```go
        

    service := New()
    secrets := NewSecrets()
    {//password expansion
        secrets["mysql"] = "~/.secret/mysql.json"
        input := "docker run --name db1 -e MYSQL_ROOT_PASSWORD=${mysql.password} -d mysql:tag"
   	    expaned, err := service.Expand(input, secrets)
   	}

   	{//username and password expansion
        secrets["pg"] = "~/.secret/pg.json"
        input := "docker run --name some-postgres -e POSTGRES_PASSWORD=${pg.password} -e POSTGRES_USER=${pg.username} -d postgres"
        expaned, err := service.Expand(input, secrets)
    }
  

```



