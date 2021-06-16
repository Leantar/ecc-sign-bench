package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

func BenchmarkECDSA_Sign_100KB(b *testing.B) {
	random := rand.Reader
	curve := elliptic.P256()
	sk, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 100)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		ECDSA_Sign(random, sk, msg[:])
	}
}


func BenchmarkECDSA_Sign_10MB(b *testing.B) {
	random := rand.Reader
	curve := elliptic.P256()
	sk, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 10)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		ECDSA_Sign(random, sk, msg[:])
	}
}

func BenchmarkECDSA_Sign_1GB(b *testing.B) {
	random := rand.Reader
	curve := elliptic.P256()
	sk, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 1000)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		ECDSA_Sign(random, sk, msg[:])
	}
}

func BenchmarkECDSA_Verify(b *testing.B) {
	random := rand.Reader
	curve := elliptic.P256()
	sk, err := ecdsa.GenerateKey(curve, random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 1000)
	rand.Read(msg)

	r, s, hash := ECDSA_Sign(random, sk, msg[:])

	for i := 0; i < b.N; i++ {
		ECDSA_Verify(&sk.PublicKey, hash[:], r ,s)
	}
}

