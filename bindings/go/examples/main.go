// Run: go run . <example>
// where <example> is one of: secretbox, box, secretstream-file, sign, password-hashing, misc
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run . <secretbox|box|secretstream-file|sign|password-hashing|misc>")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "secretbox":
		err = runSecretbox()
	case "box":
		err = runBox()
	case "secretstream-file":
		err = runSecretstreamFile()
	case "sign":
		err = runSign()
	case "password-hashing":
		err = runPasswordHashing()
	case "misc":
		err = runMisc()
	default:
		fmt.Fprintf(os.Stderr, "unknown example %q\n", os.Args[1])
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
