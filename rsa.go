package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

func RSA_PSS_Sign(sk rsa.PrivateKey, msg []byte) []byte {
	random := rand.Reader
	hasher := sha256.New()
	hasher.Write(msg)
	hash := hasher.Sum(nil)

	result, err := rsa.SignPSS(random, &sk, crypto.SHA256, hash[:], nil)
	if err != nil {
		panic(err)
	}

	return result
}

func RSA_PSS_Verify(pk rsa.PublicKey, msg, sig []byte) bool {
	return rsa.VerifyPSS(&pk, crypto.SHA256, msg[:], sig[:], nil) == nil
}