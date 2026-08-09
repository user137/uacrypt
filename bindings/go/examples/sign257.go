package main

import (
	"fmt"

	"github.com/user137/uacrypt/bindings/go/dstu"
)

// crypto_sign257 (DSTU 4145 m=257, T-199/T-204): generate a signing keypair, sign a message,
// verify it.
func runSign257() error {
	signingKey, err := dstu.GenerateSigningKey257()
	if err != nil {
		return err
	}
	defer signingKey.Close()
	verifyingKey := signingKey.VerifyingKey()
	defer verifyingKey.Close()

	message := []byte("a message whose origin and integrity matter")
	sig := signingKey.Sign(message)
	ok, err := verifyingKey.Verify(message, sig)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("verification failed")
	}
	fmt.Printf("signed and verified a %d-byte message\n", len(message))

	ok, err = verifyingKey.Verify([]byte("a different message"), sig)
	if err != nil {
		return err
	}
	if !ok {
		fmt.Println("signature over a different message correctly rejected")
	}
	return nil
}
