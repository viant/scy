package cred

import (
	"context"
	"github.com/viant/afs"
	"os"
	"path"
	"strings"
)

//DiscoverLocation discover cred location
func DiscoverLocation(ctx context.Context, name string) string {
	var candidates = []string{name}
	cwd, _ := os.Getwd()
	if cwd != "" {
		candidates = append(candidates, path.Join(cwd, name))
		candidates = append(candidates, path.Join(os.Getenv("HOME"), ".secret", name))
	}
	if !strings.Contains(name, ".") {
		candidates = append(candidates, name+".json")
		if cwd != "" {
			candidates = append(candidates, path.Join(name+".json"))
			candidates = append(candidates, path.Join(os.Getenv("HOME"), ".secret", name+".json"))
		}
	}
	fs := afs.New()
	for _, candidate := range candidates {
		if ok, _ := fs.Exists(ctx, candidate); ok {
			return candidate
		}
	}
	return ""
}
