package gcp_test

import (
	"context"
	"fmt"
	"github.com/stretchr/testify/assert"
	"github.com/viant/scy/kms"
	"github.com/viant/scy/kms/gcp"
	"golang.org/x/oauth2/google"
	"os"
	"testing"
)

func TestGCPKms_Encrypt(t *testing.T) {

	gcpProject := ""
	if cred, err := google.FindDefaultCredentials(context.TODO()); err == nil {
		gcpProject = cred.ProjectID
	}
	if gcpProject == "" {
		t.Skipf("gcp credentuals not found")
		return
	}

	cipher, err := gcp.New(context.Background())
	if !assert.Nil(t, err) {
		return
	}

	kms.Register(gcp.Schema, cipher)
	var testCases = []struct {
		description string
		key         string
		input       string
		hasError    bool
		envKey      string
		envValue    string
	}{

		{

			description: "default key",
			key:         fmt.Sprintf("gcp://kms/projects/%v/locations/us-central1/keyRings/my_ring/cryptoKeys/my_key", gcpProject),
			input:       "secret sequence @123!@#",
		},
	}

	for _, testCase := range testCases {

		if testCase.envKey != "" {
			_ = os.Setenv(testCase.envKey, testCase.envValue)
		}

		key, err := kms.NewKey(testCase.key)
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		srv, err := kms.Lookup(key.Scheme)
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		ctx := context.Background()
		encrypted, err := srv.Encrypt(ctx, key, []byte(testCase.input))
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		actual, err := srv.Decrypt(ctx, key, encrypted)
		if !assert.Nil(t, err, testCase.description) {
			continue
		}
		assert.EqualValues(t, testCase.input, string(actual), testCase.description)
	}

}
