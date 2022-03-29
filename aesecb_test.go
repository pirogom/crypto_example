package main

import (
	"fmt"
	"testing"
)

func TestAesEcb1(t *testing.T) {

	ah := AesECBHelper{}
	ah.SetSecret("sdkjfh29834yrhojkdshf892y43rfijdshflkfj824flkdjfl8942fljdslfu", AES128)

	// PKCS5
	plainText := "PIROGOM"

	fmt.Println("plain:", plainText)

	encString, encErr := ah.EncryptToBase64(plainText, PAD_PKCS5)

	if encErr != nil {
		panic(encErr)
	}

	fmt.Println("enc:", encString)

	decString, decErr := ah.DecryptFromBase64(encString, PAD_PKCS5)

	if decErr != nil {
		panic(decErr)
	}

	fmt.Println("dec:", decString)

	// PKCS7
	ah.SetSecret("sdfhio24u8ysd09f7u2oi4rfjhoiwldfj92843yflijdshflsdhjfo9284uflksdjflkdjsdfsldkjflksdjf", AES256)

	plainText = "PIROGOM_PKCS7"

	fmt.Println("plain pkcs7:", plainText)

	encString, encErr = ah.EncryptToBase64(plainText, PAD_PKCS7)

	if encErr != nil {
		panic(encErr)
	}

	fmt.Println("enc pkcs7:", encString)

	decString, decErr = ah.DecryptFromBase64(encString, PAD_PKCS7)

	if decErr != nil {
		panic(decErr)
	}

	fmt.Println("dec pkcs7:", decString)
}

func TestAesEcb2(t *testing.T) {
	ah := AesECBHelper{}
	ah.SetSecret("sdkjfh29834yrhojkdshf892y43rfijdshflkfj824flkdjfl8942fljdslfu", AES128)

	// pkcs5
	plainText := "PIROGOM"

	fmt.Println("plain:", plainText)

	encString, encErr := ah.EncryptToHex(plainText, PAD_PKCS5)

	if encErr != nil {
		panic(encErr)
	}

	fmt.Println("enc:", encString)

	decString, decErr := ah.DecryptFromHex(encString, PAD_PKCS5)

	if decErr != nil {
		panic(decErr)
	}

	fmt.Println("dec:", decString)

	// pkcs7
	ah.SetSecret("sdfhio24u8ysd09f7u2oi4rfjhoiwldfj92843yflijdshflsdhjfo9284uflksdjflkdjsdfsldkjflksdjf", AES256)

	plainText = "PIROGOM_PKCS7"

	fmt.Println("plain pkcs7:", plainText)

	encString, encErr = ah.EncryptToHex(plainText, PAD_PKCS7)

	if encErr != nil {
		panic(encErr)
	}

	fmt.Println("enc pkcs7:", encString)

	decString, decErr = ah.DecryptFromHex(encString, PAD_PKCS7)

	if decErr != nil {
		panic(decErr)
	}

	fmt.Println("dec pkcs7:", decString)

}
