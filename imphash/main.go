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

	fileContents, err := ioutil.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read %s: %s.\n", os.Args[1], err)
		os.Exit(1)
	}

	impHashes, err := imphash.ImpHashFromBytes(fileContents)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error trying to get import hash: %s.\n", err)
		return
	}
	fmt.Printf("%s: %s\n", os.Args[1], impHashes.ImpHash)
}
