package main

import (
	"fmt"

	"github.com/user137/uacrypt/bindings/go/dstu"
)

// crypto_pwhash (Argon2id): hash and verify a password.
//
// PwhashInteractive is used here so the example runs fast - PwhashModerate (the strength most
// applications should use) and PwhashSensitive both take real seconds by design.
func runPasswordHashing() error {
	password := []byte("correct horse battery staple")
	stored, err := dstu.HashPassword(password, dstu.PwhashInteractive)
	if err != nil {
		return err
	}
	fmt.Printf("stored hash: %s\n", stored)

	if !dstu.VerifyPassword(password, stored) {
		return fmt.Errorf("correct password was rejected")
	}
	fmt.Println("correct password accepted")

	if !dstu.VerifyPassword([]byte("wrong guess"), stored) {
		fmt.Println("wrong password correctly rejected")
	}
	return nil
}
