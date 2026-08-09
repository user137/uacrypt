// Run: go run . <example>
// where <example> is one of: secretbox, box, box512, secretstream-file, sign, sign257,
// password-hashing, misc
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run . <secretbox|box|box512|secretstream-file|sign|sign257|password-hashing|misc>")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "secretbox":
		err = runSecretbox()
	case "box":
		err = runBox()
	case "box512":
		err = runBox512()
	case "secretstream-file":
		err = runSecretstreamFile()
	case "sign":
		err = runSign()
	case "sign257":
		err = runSign257()
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
