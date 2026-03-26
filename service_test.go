package scy_test

import (
	"context"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"github.com/viant/scy"
	"github.com/viant/scy/cred"
	_ "github.com/viant/scy/kms/blowfish"
	"os"
	"path"
	"testing"
)

func TestService_Load(t *testing.T) {
	basePath := "/tmp/" // os.TempDir()
	var testCases = []struct {
		description string
		secret      *scy.Secret
		resource    *scy.Resource
		expect      interface{}
	}{
		{
			description: "raw secret with local fs and key",
			resource:    scy.NewResource("key", path.Join(basePath, "secret.sec"), "blowfish://default"),
			secret:      scy.NewSecret("this is secret", nil),
			expect:      "this is secret",
		},
		{
			description: "securable secrets",
			resource:    scy.NewResource(cred.Basic{}, path.Join(basePath, "json.sec"), "blowfish://default"),
			secret:      scy.NewSecret(&cred.Basic{Username: "Bob", Password: "ch@nge!Me"}, nil),
			expect:      &cred.Basic{Username: "Bob", Password: "ch@nge!Me"},
		},
		{
			description: "generic secrets",
			resource:    scy.NewResource("", path.Join(basePath, "json.sec"), "blowfish://default"),
			secret:      scy.NewSecret(&cred.Basic{Username: "Bob", Password: "ch@nge!Me"}, nil),
			expect:      &cred.Generic{SSH: cred.SSH{Basic: cred.Basic{Username: "Bob", Password: "ch@nge!Me"}}},
		},
		{
			description: "yaml secrets",
			resource:    scy.NewResource("", path.Join(basePath, "yaml.yml"), "blowfish://default"),
			secret:      scy.NewSecret(&cred.Basic{Username: "Alice", Password: "sEcReT"}, nil),
			expect:      &cred.Generic{SSH: cred.SSH{Basic: cred.Basic{Username: "Alice", Password: "sEcReT"}}},
		},
	}

	for _, testCase := range testCases {
		srv := scy.New()
		ctx := context.Background()
		testCase.secret.Resource = testCase.resource
		err := srv.Store(ctx, testCase.secret)
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		secret, err := srv.Load(ctx, testCase.resource)
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		assert.EqualValues(t, testCase.expect, secret.Target, testCase.description)
	}

}

func TestService_Load_InlinedBase64EncryptedPayload(t *testing.T) {
	ctx := context.Background()
	srv := scy.New()

	resource := scy.NewResource("key", "/tmp/inlined.sec", "blowfish://default")
	secret := scy.NewSecret("this is secret", nil)
	secret.Resource = resource
	err := srv.Store(ctx, secret)
	if !assert.Nil(t, err) {
		return
	}

	payload, err := os.ReadFile(resource.URL)
	if !assert.Nil(t, err) {
		return
	}
	inlineURL := "inlined://base64/" + base64.StdEncoding.EncodeToString(payload)

	loaded, err := srv.Load(ctx, scy.NewResource("key", inlineURL, "blowfish://default"))
	if !assert.Nil(t, err) {
		return
	}
	assert.EqualValues(t, "this is secret", loaded.Target)
}

func TestService_Load_InlinedBase64InvalidPayload(t *testing.T) {
	ctx := context.Background()
	srv := scy.New()

	_, err := srv.Load(ctx, scy.NewResource("key", "inlined://base64/not-base64!!!", "blowfish://default"))
	if !assert.NotNil(t, err) {
		return
	}
	assert.Contains(t, err.Error(), "invalid inlined base64 payload")
}
