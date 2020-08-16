package main

import (
	"github.com/malwaredb/imphash"
	"io/ioutil"
	"os"
	"fmt"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <.exe>\n", os.Args[0])
		os.Exit(1)
	}

	for _, arg := range os.Args[1:] {
		fileContents, err := ioutil.ReadFile(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read %s: %s.\n", arg, err)
			continue
		}

		impHashes, err := imphash.ImpHashFromBytes(fileContents)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse %s: %s.\n", arg, err)
			continue
		}
		fmt.Printf("%s: %s\nImpFuzzy:  %s\n", arg, impHashes.ImpHash, impHashes.ImpFuzzy)
	}
}
