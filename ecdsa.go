package main

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"io"
	"math/big"
)

func ECDSA_Sign(rand io.Reader, sk *ecdsa.PrivateKey ,msg []byte) (*big.Int, *big.Int, []byte){
	hasher := sha256.New()
	hasher.Write(msg)
	hash := hasher.Sum(nil)

	r, s, err := ecdsa.Sign(rand, sk, hash[:])
	if err != nil {
		panic(err)
	}
	return r, s, hash
}

func ECDSA_Verify(pk *ecdsa.PublicKey, hash []byte, r, s *big.Int) bool {
	return ecdsa.Verify(pk, hash[:], r, s)
}