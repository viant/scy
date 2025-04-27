package verifier

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/viant/scy"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/signer"
	_ "github.com/viant/scy/kms/blowfish"
	"github.com/viant/toolbox"
	"path"
	"testing"
	"time"
)

func TestNew(t *testing.T) {

	baseLocation := toolbox.CallerDirectory(3)
	var testCases = []struct {
		description    string
		config         *signer.Config
		verifierConfig *Config
		expiry         time.Duration
		data           interface{}
		expectUID      int
		isValid        bool
	}{
		{
			description:    "valid token with rsa",
			config:         &signer.Config{RSA: &scy.Resource{URL: path.Join(baseLocation, "testdata/private.scy"), Key: "blowfish://default"}},
			verifierConfig: &Config{RSA: []*scy.Resource{&scy.Resource{URL: path.Join(baseLocation, "testdata/public.scy"), Key: "blowfish://default"}}},
			expiry:         time.Hour,
			isValid:        true,
			data: struct {
				UID int `json:"user_id"`
			}{
				UID: 123,
			},
			expectUID: 123,
		},
		{
			description:    "valid token with hmac",
			config:         &signer.Config{HMAC: &scy.Resource{URL: path.Join(baseLocation, "testdata/hmac.scy"), Key: "blowfish://default"}},
			verifierConfig: &Config{HMAC: &scy.Resource{URL: path.Join(baseLocation, "testdata/hmac.scy"), Key: "blowfish://default"}},
			expiry:         time.Hour,
			isValid:        true,
			data: struct {
				UID int `json:"user_id"`
			}{
				UID: 123,
			},
			expectUID: 123,
		},
		{
			description:    "expired token",
			config:         &signer.Config{RSA: &scy.Resource{URL: path.Join(baseLocation, "testdata/private.scy"), Key: "blowfish://default"}},
			verifierConfig: &Config{RSA: []*scy.Resource{{URL: path.Join(baseLocation, "testdata/public.scy"), Key: "blowfish://default"}}},
			expiry:         -time.Hour,
			isValid:        false,

			data: struct {
				UID int `json:"uid"`
			}{
				UID: 123,
			},
		},
	}

	//jwtVerifier := New(&Config{HMAC: &scy.Resource{URL: path.Join(baseLocation, "testdata/keys.txt")}})
	//
	//err := jwtVerifier.Init(context.Background())
	//if err != nil {
	//	log.Fatalln(err)
	//}
	//token := "eyJhbGciOiJIUzUxMiJ9.eyJ1c2VybmFtZSI6ImN0YWJvcl92aWFudF9kZXZ0ZXN0IiwidXNlcmlkIjoyNDEsImV4cCI6MTY3OTUyNjgxNiwiaXNzIjoicGRwIn0.I4DkHwSDnPD5tTSUntVrpzgGQYx3eOPuPNrl26WgiDpFp156k1-EimMT1MpwiMaQz6tcFFmxyvH-r3ma4GiYXw"
	//jwtClaims, err := jwtVerifier.validateWithPublicKey(token)
	//fmt.Printf("%v %v\n", jwtClaims, err)
	//
	//if 1 == 1 {
	//	return
	//}
	for _, testCase := range testCases {
		ctx := context.Background()
		srv := signer.New(testCase.config)
		err := srv.Init(ctx)
		assert.Nil(t, err, testCase.description)
		tokenString, err := srv.Create(testCase.expiry, testCase.data)
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		jwtVerified := New(testCase.verifierConfig)
		err = jwtVerified.Init(ctx)
		assert.Nil(t, err, testCase.description)
		token, err := jwtVerified.Validate(ctx, tokenString)
		if !testCase.isValid {
			assert.NotNil(t, err, testCase.description)
			continue
		}
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		claims, err := sjwt.NewClaim(token)
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		assert.EqualValues(t, testCase.expectUID, claims.UserID)

	}

}
