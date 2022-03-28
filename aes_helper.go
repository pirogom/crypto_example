package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"strings"
)

// aes256 encrypt to base64 helper
type AesHelper struct {
	SecretKey string
}

/**
*	SetSecret
**/
func (a *AesHelper) SetSecret(key string) {
	if len(key) < 32 {
		panic("invalid secret key length.")
	}
	a.SecretKey = key[:32]
}

/**
*	addB64Padding
**/
func (a *AesHelper) addB64Padding(value string) string {
	m := len(value) % 4
	if m != 0 {
		value += strings.Repeat("=", 4-m)
	}
	return value
}

/**
*	removeB64Padding
**/
func (a *AesHelper) removeB64Padding(value string) string {
	return strings.Replace(value, "=", "", -1)
}

/**
*	encryptPadding
**/
func (a *AesHelper) encryptPadding(src []byte) []byte {
	padding := aes.BlockSize - len(src)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

/**
*	encryptUnPadding
**/
func (a *AesHelper) encryptUnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > length {
		return nil, errors.New("unpadding error. invalid secret key.")
	}

	return src[:(length - unpadding)], nil
}

/**
*	encryptB64
**/
func (a *AesHelper) encryptB64(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	msg := a.encryptPadding([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
	finalMsg := a.removeB64Padding(base64.URLEncoding.EncodeToString(ciphertext))
	return finalMsg, nil
}

/**
*	decryptB64
**/
func (a *AesHelper) decryptB64(key []byte, text string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	decodedMsg, err := base64.URLEncoding.DecodeString(a.addB64Padding(text))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("invalid blocksize.")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := a.encryptUnPadding(msg)
	if err != nil {
		return "", err
	}

	return string(unpadMsg), nil
}

/**
*	EncryptToBase64
**/
func (a *AesHelper) EncryptToBase64(plainText string) (string, error) {
	if a.SecretKey == "" {
		return "", errors.New("SecretKey is empty")
	}
	encBuf, err := a.encryptB64([]byte(a.SecretKey), plainText)
	if err != nil {
		return "", err
	}
	encodeBase64 := base64.StdEncoding.EncodeToString([]byte(encBuf))
	return encodeBase64, nil
}

/**
*	DecryptFromBase64
**/
func (a *AesHelper) DecryptFromBase64(encText string) (string, error) {
	if a.SecretKey == "" {
		return "", errors.New("SecretKey is empty")
	}

	decB64, berr := base64.StdEncoding.DecodeString(encText)

	if berr != nil {
		return "", berr
	}

	decodeStr, err := a.decryptB64([]byte(a.SecretKey), string(decB64))

	if err != nil {
		return "", err
	}

	return decodeStr, nil
}

/**
*	EncryptToHex
**/
func (a *AesHelper) EncryptToHex(text string) (string, error) {
	if a.SecretKey == "" {
		return "", errors.New("SecretKey is empty")
	}

	block, err := aes.NewCipher([]byte(a.SecretKey))
	if err != nil {
		return "", err
	}

	msg := a.encryptPadding([]byte(text))
	ciphertext := make([]byte, aes.BlockSize+len(msg))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	cfb := cipher.NewCFBEncrypter(block, iv)
	cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(msg))
	finalMsg := hex.EncodeToString(ciphertext)
	return finalMsg, nil
}

/**
*	DecryptFromHex
**/
func (a *AesHelper) DecryptFromHex(hexStr string) (string, error) {
	if a.SecretKey == "" {
		return "", errors.New("SecretKey is empty")
	}

	decodedMsg, hexErr := hex.DecodeString(hexStr)

	if hexErr != nil {
		return "", hexErr
	}

	block, err := aes.NewCipher([]byte(a.SecretKey))
	if err != nil {
		return "", err
	}

	if (len(decodedMsg) % aes.BlockSize) != 0 {
		return "", errors.New("invalid blocksize.")
	}

	iv := decodedMsg[:aes.BlockSize]
	msg := decodedMsg[aes.BlockSize:]

	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(msg, msg)

	unpadMsg, err := a.encryptUnPadding(msg)
	if err != nil {
		return "", err
	}

	return string(unpadMsg), nil
}
