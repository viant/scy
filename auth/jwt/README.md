## JWT toolkit





### Signing and verifying JWT token with custom RSA key

1. Generating RSA key: `
  ```bash
# Created Private key
ssh-keygen -t rsa -f key.pem -m pem or openssl genpkey -out private.txt -outform PEM -algorithm RSA -pkeyopt rsa_keygen_bits:4096
#  Created public key with:
openssl pkey -inform PEM -outform PEM -in private.txt -pubout -out public.txt
```
2. Secure rsa.json with scy client (use one of the supported security store)
   ```bash
    scy -m=secure -s=public.txt -d=public.scy -t=raw -k=blowfish://default ## on prod, use secure store instead of local fs
    scy -m=secure -s=private.txt -d=private.scy -t=raw -k=blowfish://default ## on prod, use secure store instead of local fs
      ```
3. To sign JWT Claim
a) Creates jwt [Claim](https://github.com/viant/scy/blob/main/auth/jwt/claims.go) in JSON format
```bash
   echo '{"user_id":123,"email":"dev@viantinc.com"}' > claims.json 
```
b) Sign claim   
```bash
   scy -m=signJwt -s=claims.json -r=private.scy -k=blowfish://default
``` 

4 To verify JWT Claim
   scy -m=verifyJwt -s=token.json -r=public.scy -k=blowfish://default
``` 
