package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/certen/independant-validator/accumulate-lite-client-2/liteclient/proof/production"
)

func main() {
	var (
		help = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		fmt.Println("Devnet Account Explorer")
		fmt.Println("\nUsage:")
		fmt.Println("  test-accounts               # Explore devnet accounts")
		fmt.Println("  test-accounts -endpoint URL # Use custom endpoint")
		fmt.Println("\nThis tool will:")
		fmt.Println("  - Map network topology")
		fmt.Println("  - Test receipt generation")
		fmt.Println("  - Attempt account creation")
		fmt.Println("  - Show BPT components")
		os.Exit(0)
	}

	// Run the account tests
	production.RunAccountTests()
}