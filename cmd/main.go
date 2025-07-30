package main

import (
	"fmt"
	"os"

	"toolkit/cmd/recon"
)

func main() {
	if err := recon.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
