package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/amiryahaya/triton/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		if errors.Is(err, cmd.ErrPolicyFail) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
