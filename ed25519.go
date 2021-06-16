package main

import (
	"crypto/ed25519"
)

func Ed25519_Sign(sk ed25519.PrivateKey, msg []byte) []byte {
	return ed25519.Sign(sk, msg[:])
}

func Ed25519_Verify(pk ed25519.PublicKey, msg, sig []byte) bool {
	return ed25519.Verify(pk, msg[:], sig[:])
}