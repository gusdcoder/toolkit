package main

import (
	"fmt"
	"os"
	
	"github.com/recon-platform/core/cmd/recon"
)

func main() {
	if err := recon.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}