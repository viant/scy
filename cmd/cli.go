package cmd

import (
	"github.com/jessevdk/go-flags"
	"log"
)

func Run(args []string) {
	// For backward compatibility, we still use the Options struct
	options := &Options{}
	options.Init(args[0])
	_, err := flags.ParseArgs(options, args)
	if err != nil {
		log.Fatal(err)
	}
}


// RunWithCommands runs the command-based CLI
func RunWithCommands(args []string) {
	Run(args)
}
