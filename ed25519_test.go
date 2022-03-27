package main

import (
	"fmt"
	"os"
	"testing"
)

func TestEcdsa1(t *testing.T) {

	eh := ECDSAHelper{}

	if err := eh.Generate(); err != nil {
		panic(err)
	}

	msg := "ed25519 test msg 1"
	failMsg := "ed25519 test msg failed1"

	signedBuf, err := eh.Sign(msg)

	if err != nil {
		panic(err)
	}

	failSignedBuf := []byte{0xf, 0xf}

	if eh.Verify(msg, signedBuf) {
		fmt.Println("Verify OK")
	} else {
		fmt.Println("Verify Failed")
	}

	if eh.Verify(failMsg, signedBuf) {
		fmt.Println("Verify OK")
	} else {
		fmt.Println("Verify Failed")
	}

	if eh.Verify(msg, failSignedBuf) {
		fmt.Println("Verify OK")
	} else {
		fmt.Println("Verify Failed")
	}
}

func TestEcdsa2(t *testing.T) {
	const (
		privateKeyFile = "ed25519_private.pem"
		publicKeyFile  = "ed25519_public.pem"
	)

	eh := ECDSAHelper{}

	if err := eh.Generate(); err != nil {
		panic(err)
	}

	if err := eh.PrivateKeyToFile(privateKeyFile); err != nil {
		panic(err)
	}

	if err := eh.PublicKeyToFile(publicKeyFile); err != nil {
		panic(err)
	}

	msg := "ed25519 test msg 2"

	signedBuf, err := eh.Sign(msg)

	if err != nil {
		panic(err)
	}

	eh2 := ECDSAHelper{}

	if err := eh2.PrivateKeyFromFile(privateKeyFile); err != nil {
		panic(err)
	}
	if err := eh2.PublicKeyFromFile(publicKeyFile); err != nil {
		panic(err)
	}

	if eh2.Verify(msg, signedBuf) {
		fmt.Println("Verify OK")
	} else {
		fmt.Println("Verify Failed")
	}
	os.Remove(privateKeyFile)
	os.Remove(publicKeyFile)
}
