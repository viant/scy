//go:build !integration

package scy_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestMain ensures accidental NewCLI() use never invokes the real op binary
// (which triggers 1Password desktop prompts) during regular unit tests.
// Excluded from the integration build (see integration_test.go) so that
// build's TestIntegrationLoad_OpURL actually reaches the real op CLI instead
// of silently getting this fake override too.
func TestMain(m *testing.M) {
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		fakeOP := filepath.Join(filepath.Dir(filename), "testdata", "fake-op.sh")
		_ = os.Setenv("OP_CLI", fakeOP)
	}
	os.Exit(m.Run())
}
