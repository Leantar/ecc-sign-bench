package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func BenchmarkEd25519_Sign_100KB(b *testing.B) {
	random := rand.Reader
	_, sk, err := ed25519.GenerateKey(random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 100)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		Ed25519_Sign(sk, msg[:])
	}
}


func BenchmarkEd25519_Sign_10MB(b *testing.B) {
	random := rand.Reader
	_, sk, err := ed25519.GenerateKey(random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 10)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		Ed25519_Sign(sk, msg[:])
	}
}

func BenchmarkEd25519_Sign_1GB(b *testing.B) {
	random := rand.Reader
	_, sk, err := ed25519.GenerateKey(random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 1000)
	rand.Read(msg)

	for i := 0; i < b.N; i++ {
		Ed25519_Sign(sk, msg[:])
	}
}

func BenchmarkEd25519_Verify(b *testing.B) {
	random := rand.Reader
	pk, sk, err := ed25519.GenerateKey(random)
	if err != nil {
		panic(err)
	}

	msg := make([]byte, 1000 * 1000 * 1000)
	rand.Read(msg)

	sig := Ed25519_Sign(sk, msg[:])

	for i := 0; i < b.N; i++ {
		Ed25519_Verify(pk, msg[:], sig[:])
	}
}
