package cmd

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/viant/scy"
	"log"
)

func Run(args []string) {
	if shouldPrintVersion(args) {
		fmt.Println(versionString())
		return
	}

	// For backward compatibility, we still use the Options struct
	options := &Options{}
	if len(args) > 0 {
		options.Init(args[0])
	}
	_, err := flags.ParseArgs(options, args)
	if err != nil {
		log.Fatal(err)
	}
}

func shouldPrintVersion(args []string) bool {
	return len(args) == 1 && (args[0] == "-v" || args[0] == "--version")
}

func versionString() string {
	if version := scy.ReleaseVersion(); version != "" {
		return version
	}
	return "dev"
}

// RunWithCommands runs the command-based CLI
func RunWithCommands(args []string) {
	Run(args)
}
