package scy_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/viant/scy"

	_ "github.com/viant/afsc/op"
)

func TestMain(m *testing.M) {
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		fakeOP := filepath.Join(filepath.Dir(filename), "testdata", "fake-op.sh")
		_ = os.Setenv("OP_CLI", fakeOP)
	}
	os.Exit(m.Run())
}

func TestService_Load_OpURL(t *testing.T) {
	ctx := context.Background()
	srv := scy.New()

	resource := scy.NewResource("", "op://Private/viant-e2e.json/notesPlain", "")
	secret, err := srv.Load(ctx, resource)
	require.NoError(t, err)
	require.NotEmpty(t, secret.String())

	var payload map[string]interface{}
	require.NoError(t, secret.Decode(&payload))
	assert.Equal(t, "service_account", payload["type"])
	assert.Equal(t, "test", payload["project_id"])
}
