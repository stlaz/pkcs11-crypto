package main

import "os"

func main() {
	cmd := NewCryptoUtilCommand()

	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
