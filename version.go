package scy

import (
	_ "embed"
	"strings"
)

//go:embed Version
var embeddedVersion string

func ReleaseVersion() string {
	return strings.TrimSpace(embeddedVersion)
}
