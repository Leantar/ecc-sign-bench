package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"testing"
)

func BenchmarkRSA_PSS_Sign_100KB(b *testing.B) {
	random := rand.Reader
	sk, err := rsa.GenerateKey(random, 3072)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 100)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		RSA_PSS_Sign(*sk, msg[:])
	}
}


func BenchmarkRSA_PSS_Sign_10MB(b *testing.B) {
	random := rand.Reader
	sk, err := rsa.GenerateKey(random, 3072)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 10)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		RSA_PSS_Sign(*sk, msg[:])
	}
}

func BenchmarkRSA_PSS_Sign_1GB(b *testing.B) {
	random := rand.Reader
	sk, err := rsa.GenerateKey(random, 3072)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 1000)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		RSA_PSS_Sign(*sk, msg[:])
	}
}

func BenchmarkRSA_PSS_Verify(b *testing.B) {
	random := rand.Reader
	sk, err := rsa.GenerateKey(random, 3072)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 1000)
	rand.Read(msg)

	sig := RSA_PSS_Sign(*sk, msg[:])
	hasher := sha256.New()
	hasher.Write(msg)
	hash := hasher.Sum(nil)

	for i := 0; i < b.N; i++ {
		RSA_PSS_Verify(sk.PublicKey, hash[:], sig[:])
	}
}
