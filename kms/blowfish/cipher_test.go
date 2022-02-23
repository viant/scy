package blowfish_test

import (
	"context"
	"github.com/stretchr/testify/assert"
	"github.com/viant/scy/kms"
	"os"
	"testing"
)

func TestBlowfish_Encrypt(t *testing.T) {

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
			key:         "blowfish://default",
			input:       "secret sequence @123!@#",
		},
		{
			description: "env key",
			key:         "blowfish://env/myKey",
			input:       "123456789!@#$%^&*",
			envKey:      "myKey",
			envValue:    "1234567899",
		},
		{
			description: "env key",
			key:         "blowfish://env/myKey",
			input:       "123456789!@#$%^&*",
			envKey:      "myKey",
			envValue:    "this is my key",
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
