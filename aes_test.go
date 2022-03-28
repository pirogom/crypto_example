package main

import (
	"fmt"
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
