package verifier

import (
	"context"
	"path"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/viant/scy"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/signer"
	_ "github.com/viant/scy/kms/blowfish"
	"github.com/viant/toolbox"
)

func TestNew(t *testing.T) {
	baseLocation := toolbox.CallerDirectory(3)
	rsaPrivate := &scy.Resource{URL: path.Join(baseLocation, "testdata/private.scy"), Key: "blowfish://default"}
	rsaPublic := &scy.Resource{URL: path.Join(baseLocation, "testdata/public.scy"), Key: "blowfish://default"}
	hmacKey := &scy.Resource{URL: path.Join(baseLocation, "testdata/hmac.scy"), Key: "blowfish://default"}

	testCases := []struct {
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
			config:         &signer.Config{RSA: rsaPrivate},
			verifierConfig: &Config{RSA: []*scy.Resource{rsaPublic}},
			expiry:         time.Hour,
			isValid:        true,
			data: struct {
				UID int `json:"user_id"`
			}{UID: 123},
			expectUID: 123,
		},
		{
			description:    "valid token with hmac",
			config:         &signer.Config{HMAC: hmacKey},
			verifierConfig: &Config{HMAC: hmacKey},
			expiry:         time.Hour,
			isValid:        true,
			data:           &sjwt.Claims{UserID: 123},
			expectUID:      123,
		},
		{
			description: "resource rule uses hs256 and overrides default rsa",
			config: &signer.Config{
				RSA: rsaPrivate,
				Rules: []*signer.Rule{
					{
						Resource:  []string{"mcp"},
						Algorithm: "HS256",
						HMAC:      hmacKey,
					},
				},
			},
			verifierConfig: &Config{
				RSA: []*scy.Resource{rsaPublic},
				Rules: []*Rule{
					{
						Resource:  []string{"mcp"},
						Algorithm: "HS256",
						HMAC:      hmacKey,
					},
				},
			},
			expiry:  time.Hour,
			isValid: true,
			data: &sjwt.Claims{
				UserID: 123,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: []string{"mcp"},
				},
			},
			expectUID: 123,
		},
		{
			description: "default rsa is used when no resource rule matches",
			config: &signer.Config{
				RSA: rsaPrivate,
				Rules: []*signer.Rule{
					{
						Resource:  []string{"mcp"},
						Algorithm: "HS256",
						HMAC:      hmacKey,
					},
				},
			},
			verifierConfig: &Config{
				RSA: []*scy.Resource{rsaPublic},
				Rules: []*Rule{
					{
						Resource:  []string{"mcp"},
						Algorithm: "HS256",
						HMAC:      hmacKey,
					},
				},
			},
			expiry:  time.Hour,
			isValid: true,
			data: &sjwt.Claims{
				UserID: 321,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: []string{"web"},
				},
			},
			expectUID: 321,
		},
		{
			description: "resource rule blocks fallback to default algorithm",
			config:      &signer.Config{RSA: rsaPrivate},
			verifierConfig: &Config{
				RSA: []*scy.Resource{rsaPublic},
				Rules: []*Rule{
					{
						Resource:  []string{"mcp"},
						Algorithm: "HS256",
						HMAC:      hmacKey,
					},
				},
			},
			expiry:  time.Hour,
			isValid: false,
			data: &sjwt.Claims{
				UserID: 123,
				RegisteredClaims: jwt.RegisteredClaims{
					Audience: []string{"mcp"},
				},
			},
		},
		{
			description:    "expired token",
			config:         &signer.Config{RSA: rsaPrivate},
			verifierConfig: &Config{RSA: []*scy.Resource{rsaPublic}},
			expiry:         -time.Hour,
			isValid:        false,
			data: struct {
				UID int `json:"uid"`
			}{UID: 123},
		},
	}

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
