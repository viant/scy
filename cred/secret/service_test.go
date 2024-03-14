package secret_test

import (
	"context"
	"embed"
	"github.com/stretchr/testify/assert"
	_ "github.com/viant/afs/embed"
	"github.com/viant/scy/cred/secret"
	_ "github.com/viant/scy/kms/blowfish"

	"testing"
)

//go:embed testdata/*
var secretFs embed.FS

func TestNewSecrets(t *testing.T) {

	var testCases = []struct {
		options []secret.Option
		secrets map[secret.Key]secret.Resource
		input   string
		expect  string
	}{
		{
			secrets: secret.NewSecrets(map[string]string{
				"dbuser":    "testdata/mysql",
				"viant-e2e": "viant-e2e",
			}),
			input:  "-u ${dbuser.username} -p ${dbuser.password}",
			expect: "-u root -p dev",
			options: []secret.Option{
				secret.WithFileSystem(&secretFs),
			},
		},
	}

	for _, testCase := range testCases {
		srv := secret.New(testCase.options...)
		actual, err := srv.Expand(context.Background(), testCase.input, testCase.secrets)
		assert.Nil(t, err)
		assert.EqualValues(t, testCase.expect, actual)
	}

}
