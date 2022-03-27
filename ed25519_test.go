package main

import (
	"fmt"
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
