package main

import (
	"fmt"
	"os"
	"testing"
)

func TestRsa1(t *testing.T) {
	rh := RSAHelper{}

	if err := rh.GenerateKey(2048); err != nil {
		panic(err)
	}

	plainText := "rsa encrypt test 1"
	fmt.Println("plain text:", plainText)
	encString, err := rh.EncryptString(plainText)

	if err != nil {
		panic(err)
	}
	fmt.Println("EhcryptString:", encString)

	decString, decErr := rh.DecryptString(encString)

	if decErr != nil {
		panic(decErr)
	}

	fmt.Println("Descrypt String:", decString)
}

func TestRsa2(t *testing.T) {
	const (
		privateKeyFile = "rsa_private.pem"
		publicKeyFile  = "rsa_public.pem"
	)
	rh := RSAHelper{}

	if err := rh.GenerateKey(2048); err != nil {
		panic(err)
	}

	if err := rh.PrivateToFilePEM(privateKeyFile); err != nil {
		panic(err)
	}

	if err := rh.PublicToFilePEM(publicKeyFile); err != nil {
		panic(err)
	}

	plainText := "rsa encrypt test 2"

	fmt.Println("plain text:", plainText)

	encBuf, err := rh.EncryptByte([]byte(plainText))
	if err != nil {
		panic(err)
	}

	rh2 := RSAHelper{}

	if err := rh2.PrivateFromFilePEM(privateKeyFile); err != nil {
		panic(err)
	}
	if err := rh2.PublicFromFilePEM(publicKeyFile); err != nil {
		panic(err)
	}

	decBuf, decErr := rh2.DecryptByte(encBuf)

	if decErr != nil {
		panic(decErr)
	}

	fmt.Println("Decrypt String:", string(decBuf))

	os.Remove(privateKeyFile)
	os.Remove(publicKeyFile)
}
