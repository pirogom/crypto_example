package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
)

type ECDSAHelper struct {
	PrivateKey *ed25519.PrivateKey
	PublicKey  *ed25519.PublicKey
}

/**
*	Generate
**/
func (e *ECDSAHelper) Generate() error {

	if e.PrivateKey != nil {
		e.PrivateKey = nil
		e.PublicKey = nil
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)

	if err != nil {
		return err
	}

	e.PrivateKey = &privateKey
	e.PublicKey = &publicKey
	return nil
}

/**
*	EncodePrivateKey
**/
func (e *ECDSAHelper) EncodePrivateKey() ([]byte, error) {
	if e.PrivateKey == nil {
		return nil, errors.New("private key is nil")
	}

	encBuf := pem.EncodeToMemory(
		&pem.Block{
			Type:  "ED25519 PRIVATE KEY",
			Bytes: *e.PrivateKey,
		})

	return encBuf, nil
}

/**
*	DecodePrivateKey
**/
func (e *ECDSAHelper) DecodePrivateKey(encKey []byte) error {
	if e.PrivateKey != nil {
		e.PrivateKey = nil
	}

	block, _ := pem.Decode(encKey)

	if block == nil {
		return errors.New("failed to find ED25519 PRIVATE KEY")
	}

	if block.Type != "ED25519 PRIVATE KEY" {
		return fmt.Errorf("%s is invalid block type", block.Type)
	}
	e.PrivateKey = (*ed25519.PrivateKey)(&block.Bytes)
	return nil
}

/**
*	PrivateKeyToFile
**/
func (e *ECDSAHelper) PrivateKeyToFile(fname string) error {
	if e.PrivateKey == nil {
		return errors.New("private key is nil")
	}
	enc, err := e.EncodePrivateKey()

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fname, enc, 0644)

	if err != nil {
		return err
	}
	return nil
}

/**
*	PrivateKeyFromFile
**/
func (e *ECDSAHelper) PrivateKeyFromFile(fname string) error {
	if e.PrivateKey != nil {
		e.PrivateKey = nil
	}

	buf, err := ioutil.ReadFile(fname)

	if err != nil {
		return err
	}

	err = e.DecodePrivateKey(buf)

	if err != nil {
		return err
	}
	return nil
}

/**
*	EncodePublicKey
**/
func (e *ECDSAHelper) EncodePublicKey() ([]byte, error) {
	if e.PublicKey == nil {
		return nil, errors.New("public key is nil")
	}

	encBuf := pem.EncodeToMemory(
		&pem.Block{
			Type:  "ED25519 PUBLIC KEY",
			Bytes: *e.PublicKey,
		})

	return encBuf, nil
}

/**
*	DecodePublicKey
**/
func (e *ECDSAHelper) DecodePublicKey(encKey []byte) error {
	if e.PublicKey != nil {
		e.PublicKey = nil
	}

	block, _ := pem.Decode(encKey)

	if block == nil {
		return errors.New("failed to find ED25519 PUBLIC KEY")
	}

	if block.Type != "ED25519 PUBLIC KEY" {
		return fmt.Errorf("%s is invalid block type", block.Type)
	}

	e.PublicKey = (*ed25519.PublicKey)(&block.Bytes)

	return nil
}

/**
*	PublicKeyToFile
**/
func (e *ECDSAHelper) PublicKeyToFile(fname string) error {
	if e.PublicKey == nil {
		return errors.New("public key is nil")
	}
	enc, err := e.EncodePublicKey()

	if err != nil {
		return err
	}

	err = ioutil.WriteFile(fname, enc, 0644)

	if err != nil {
		return err
	}
	return nil
}

/**
*	PublicKeyFromFile
**/
func (e *ECDSAHelper) PublicKeyFromFile(fname string) error {
	if e.PublicKey != nil {
		e.PrivateKey = nil
	}

	buf, err := ioutil.ReadFile(fname)

	if err != nil {
		return err
	}

	err = e.DecodePublicKey(buf)

	if err != nil {
		return err
	}
	return nil
}

/**
*	Sign
**/
func (e *ECDSAHelper) Sign(msg string) ([]byte, error) {
	if e.PrivateKey == nil {
		return nil, errors.New("private key is nil")
	}

	hash := sha256.Sum256([]byte(msg))
	signed := ed25519.Sign(*e.PrivateKey, hash[:])

	return signed, nil
}

/**
*	SignToString
**/
func (e *ECDSAHelper) SignToString(msg string) (string, error) {
	signed, err := e.Sign(msg)

	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signed), nil
}

/**
* SignToPEM
**/
func (e *ECDSAHelper) SignToPEM(msg string, blockType string) ([]byte, error) {
	signed, err := e.Sign(msg)

	if err != nil {
		return nil, err
	}

	encBuf := pem.EncodeToMemory(
		&pem.Block{
			Type:  blockType,
			Bytes: signed,
		})

	return encBuf, nil
}

/**
*	SignFromPEM
**/
func (e *ECDSAHelper) SignFromPEM(pemBuf []byte, blockType string) ([]byte, error) {
	block, _ := pem.Decode(pemBuf)

	if block == nil {
		return nil, errors.New("failed to find ED25519 PUBLIC KEY")
	}

	if block.Type != blockType {
		return nil, fmt.Errorf("%s is invalid block type", block.Type)
	}

	return block.Bytes, nil
}

/**
*	IsValidSignPEM
**/
func (e *ECDSAHelper) IsValidSignPEM(pemBuf []byte, blockType string) bool {
	block, _ := pem.Decode(pemBuf)

	if block == nil {
		return false
	}

	if block.Type != blockType {
		return false
	}
	return true
}

/**
*	Verify
**/
func (e *ECDSAHelper) Verify(msg string, signed []byte) bool {
	if e.PublicKey == nil {
		return false
	}
	hash := sha256.Sum256([]byte(msg))

	return ed25519.Verify(*e.PublicKey, hash[:], signed)
}

/**
*	VerifyString
**/
func (e *ECDSAHelper) VerifyString(msg string, signed string) bool {
	byteSigned, err := hex.DecodeString(signed)

	if err != nil {
		return false
	}

	return e.Verify(msg, byteSigned)
}
