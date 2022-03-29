package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

type AesBits uint8
type AesPadMode uint8

const (
	AES128 AesBits = 0
	AES256 AesBits = 1

	PAD_PKCS5 AesPadMode = 0
	PAD_PKCS7 AesPadMode = 1
)

// aes256(ECB) encrypt to base64 helper
type AesECBHelper struct {
	SecretKey string
	Key       []byte
}

/**
*	SetSecret
**/
func (a *AesECBHelper) SetSecret(key string, bits AesBits) {
	switch bits {
	case AES128:
		if len(key) < 16 {
			panic("invalid secret key length.")
		}
		a.SecretKey = key[:16]
		a.Key = []byte(a.SecretKey)
	case AES256:
		if len(key) < 32 {
			panic("invalid secret key length.")
		}
		a.SecretKey = key[:32]
		a.Key = []byte(a.SecretKey)
	default:
		panic("bad aes bits")
	}
}

/**
*	PKCS5Padding
**/
func (a *AesECBHelper) PKCS5Padding(ct []byte, bsize int) []byte {
	padding := bsize - len(ct)%bsize
	pad := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ct, pad...)
}

/**
*	PKCS5UnPadding
**/
func (a *AesECBHelper) PKCS5UnPadding(od []byte) []byte {
	len := len(od)
	up := int(od[len-1])
	return od[:(len - up)]
}

/**
*	PKCS7Padding
**/
func (a *AesECBHelper) PKCS7Padding(ct []byte, bsize int) ([]byte, error) {
	if bsize <= 0 {
		return nil, fmt.Errorf("invalid block size %d", bsize)
	}
	padlen := 1
	for ((len(ct) + padlen) % bsize) != 0 {
		padlen = padlen + 1
	}
	pad := bytes.Repeat([]byte{byte(padlen)}, padlen)
	return append(ct, pad...), nil
}

/**
*	PKCS7UnPadding
**/
func (a *AesECBHelper) PKCS7UnPadding(od []byte) ([]byte, error) {
	padlen := int(od[len(od)-1])
	pad := od[len(od)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}
	return od[:len(od)-padlen], nil
}

/**
*	Decrypt
**/
func (a *AesECBHelper) Decrypt(crypted []byte, pm AesPadMode) ([]byte, error) {
	if a.SecretKey == "" {
		return nil, errors.New("secret key is empty")
	}

	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}
	blockMode := NewECBDecrypter(block)
	origData := make([]byte, len(crypted))
	blockMode.CryptBlocks(origData, crypted)

	switch pm {
	case PAD_PKCS5:
		origData = a.PKCS5UnPadding(origData)
	case PAD_PKCS7:
		origData, err = a.PKCS7UnPadding(origData)
		if err != nil {
			return nil, err
		}
	default:
		origData, err = a.PKCS7UnPadding(origData)
		if err != nil {
			return nil, err
		}
	}
	return origData, nil
}

/**
*	Encrypt
**/
func (a *AesECBHelper) Encrypt(src string, pm AesPadMode) ([]byte, error) {
	if a.SecretKey == "" {
		return nil, errors.New("secret key is empty")
	}
	block, err := aes.NewCipher(a.Key)
	if err != nil {
		return nil, err
	}
	if src == "" {
		return nil, errors.New("plain text is empty")
	}
	ecb := NewECBEncrypter(block)
	content := []byte(src)

	switch pm {
	case PAD_PKCS5:
		content = a.PKCS5Padding(content, block.BlockSize())
	case PAD_PKCS7:
		content, err = a.PKCS7Padding(content, block.BlockSize())
		if err != nil {
			return nil, err
		}
	default:
		content, err = a.PKCS7Padding(content, block.BlockSize())
		if err != nil {
			return nil, err
		}
	}
	crypted := make([]byte, len(content))
	ecb.CryptBlocks(crypted, content)
	return crypted, nil
}

/**
*	EncryptToBase64
**/
func (a *AesECBHelper) EncryptToBase64(plainText string, pm AesPadMode) (string, error) {
	enc, encErr := a.Encrypt(plainText, pm)

	if encErr != nil {
		return "", encErr
	}
	return base64.StdEncoding.EncodeToString(enc), nil
}

/**
*	DecryptFromBase64
**/
func (a *AesECBHelper) DecryptFromBase64(encText string, pm AesPadMode) (string, error) {

	decB64, berr := base64.StdEncoding.DecodeString(encText)

	if berr != nil {
		return "", berr
	}

	dec, decErr := a.Decrypt(decB64, pm)

	if decErr != nil {
		return "", decErr
	}
	return string(dec), nil
}

/**
*	EncryptToHex
**/
func (a *AesECBHelper) EncryptToHex(plainText string, pm AesPadMode) (string, error) {
	enc, encErr := a.Encrypt(plainText, pm)

	if encErr != nil {
		return "", encErr
	}
	return hex.EncodeToString(enc), nil
}

/**
*	DecryptFromHex
**/
func (a *AesECBHelper) DecryptFromHex(encText string, pm AesPadMode) (string, error) {

	decode, decodeErr := hex.DecodeString(encText)

	if decodeErr != nil {
		return "", decodeErr
	}

	dec, decErr := a.Decrypt(decode, pm)

	if decErr != nil {
		return "", decErr
	}
	return string(dec), nil
}

/**
* ECB Block struct
**/
type ecb struct {
	b         cipher.Block
	blockSize int
}

/**
*	NewECB
**/
func newECB(b cipher.Block) *ecb {
	nb := ecb{}
	nb.b = b
	nb.blockSize = b.BlockSize()
	return &nb
}

/**
*	ecbEncrypter
**/
type ecbEncrypter ecb

/**
*	NewECBEncrypter
**/
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

/**
*	BlockSize
**/
func (x *ecbEncrypter) BlockSize() int {
	return x.blockSize
}

/**
*	CryptBlocks
**/
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

/**
*	ecbDecrypter
**/
type ecbDecrypter ecb

/**
*	NewECBDecrypter
**/
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

/**
*	BlockSize
**/
func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}

/**
*	CryptBlocks
**/
func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
