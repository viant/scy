//go:build integration

package scy_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/viant/scy"

	_ "github.com/viant/afsc/op"
)

// TestIntegrationLoad_OpURL exercises a real 1Password secret via scy.Load.
//
// Run manually (not from CI or Cursor):
//
//	op signin
//	export OP_INTEGRATION_REF='op://Private/viant-e2e.json/notesPlain'
//	go test . -tags=integration -run TestIntegrationLoad_OpURL -count=1 -v
func TestIntegrationLoad_OpURL(t *testing.T) {
	ref := os.Getenv("OP_INTEGRATION_REF")
	if ref == "" {
		t.Skip("set OP_INTEGRATION_REF to an op:// secret reference")
	}

	srv := scy.New()
	secret, err := srv.Load(context.Background(), scy.NewResource("", ref, ""))
	require.NoError(t, err)
	require.NotEmpty(t, secret.String())
	t.Logf("read %d bytes from %s", len(secret.String()), ref)
}
