package verifier

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/viant/scy"
	sjwt "github.com/viant/scy/auth/jwt"
	"github.com/viant/scy/auth/jwt/singer"
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
		config         *singer.Config
		verifierConfig *Config
		expiry         time.Duration
		data           interface{}
		expectUID      int
		isValid        bool
	}{
		{
			description:    "valid token",
			config:         &singer.Config{RSA: &scy.Resource{URL: path.Join(baseLocation, "testdata/private.scy"), Key: "blowfish://default"}},
			verifierConfig: &Config{RSA: &scy.Resource{URL: path.Join(baseLocation, "testdata/public.scy"), Key: "blowfish://default"}},
			expiry:         time.Hour,
			isValid:        true,
			data: struct {
				UID int `json:"uid"`
			}{
				UID: 123,
			},
			expectUID: 123,
		},
		{
			description:    "expired token",
			config:         &singer.Config{RSA: &scy.Resource{URL: path.Join(baseLocation, "testdata/private.scy"), Key: "blowfish://default"}},
			verifierConfig: &Config{RSA: &scy.Resource{URL: path.Join(baseLocation, "testdata/public.scy"), Key: "blowfish://default"}},
			expiry:         -time.Hour,
			isValid:        false,

			data: struct {
				UID int `json:"uid"`
			}{
				UID: 123,
			},
		},
	}

	for _, testCase := range testCases {
		ctx := context.Background()
		srv := singer.New(testCase.config)
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
