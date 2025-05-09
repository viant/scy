package cmd

import (
	"os"
	"path"
	"strings"
)

func normalizeLocation(location string) string {
	if location == "" {
		return ""
	}
	if strings.HasPrefix(location, "~") {
		return os.Getenv("HOME") + location[1:]
	}
	if !strings.Contains(location, ":/") && !strings.HasPrefix(location, "/") {
		cwd, _ := os.Getwd()
		return path.Join(cwd, location)
	}
	return location
}

