package main

import (
	"fmt"
	"io/ioutil"
	"testing"
)

func TestAes1(t *testing.T) {
	ah := AesHelper{}

	ah.SetSecret("akjsdhiuqwe1i23eyjkwdhf92yehf98213yrkjdshfdkufy2io3frkjsdhfkjsdhfk2h34")

	encStr, encErr := ah.EncryptToBase64("[PIROGOM]")
	if encErr != nil {
		panic(encErr)
	}
	fmt.Println("enc", encStr)
	decStr, decErr := ah.DecryptFromBase64(encStr)
	if decErr != nil {
		panic(decErr)
	}
	fmt.Println("dec", decStr)
}

func TestAes2(t *testing.T) {
	ah := AesHelper{}

	ah.SetSecret("weiru2039rulksdjf892yrfidjf82409yfjwhg9724tgjukhslkdfyho8dyf2o34jhf")

	encStr, encErr := ah.EncryptToHex("[PIROGOM]")
	if encErr != nil {
		panic(encErr)
	}
	fmt.Println("enc", encStr)
	decStr, decErr := ah.DecryptFromHex(encStr)

	if decErr != nil {
		panic(decErr)
	}
	fmt.Println("dec", decStr)
}

func TestAes3(t *testing.T) {
	ah := AesHelper{}

	ah.SetSecret("wer20389rlkshdfi8ofh2ojflkdsjfldisufwezdfsdfwe")

	readBuf, readErr := ioutil.ReadFile("GO_LICENSE.txt")

	if readErr != nil {
		panic(readErr)
	}

	encStr, encErr := ah.EncryptToBase64(string(readBuf))
	if encErr != nil {
		panic(encErr)
	}
	fmt.Println("enc(base64)", encStr)
	decStr, decErr := ah.DecryptFromBase64(encStr)

	if decErr != nil {
		panic(decErr)
	}
	fmt.Println("dec(base64)", decStr)

	encStr, encErr = ah.EncryptToHex(string(readBuf))
	if encErr != nil {
		panic(encErr)
	}
	fmt.Println("enc(hex)", encStr)
	decStr, decErr = ah.DecryptFromHex(encStr)

	if decErr != nil {
		panic(decErr)
	}
	fmt.Println("dec(hex)", decStr)
}
