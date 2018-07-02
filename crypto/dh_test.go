package crypto_test

import (
	"bytes"
	"testing"

	"github.com/jamesbcook/chatbot-external-api/crypto"
)

func TestCreateKeysDH(t *testing.T) {
	ecdh := &crypto.ECDH{}
	if err := ecdh.CreateKeys(); err != nil {
		t.Fatal(err)
	}
	zeroed := [32]byte{0}
	if bytes.Compare(ecdh.PrivateKey[:], zeroed[:]) == 0 {
		t.Fatal("Private key wasn't filled")
	}
	if bytes.Compare(ecdh.PublicKey[:], zeroed[:]) == 0 {
		t.Fatal("Public key wasn't filled")
	}
}

func TestGenerateSharedSecret(t *testing.T) {
	ourKeys := &crypto.ECDH{}
	if err := ourKeys.CreateKeys(); err != nil {
		t.Fatal(err)
	}
	theirKeys := &crypto.ECDH{}
	if err := theirKeys.CreateKeys(); err != nil {
		t.Fatal(err)
	}
	ourShared, err := ourKeys.GenerateSharedSecret(&theirKeys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	theirShared, err := theirKeys.GenerateSharedSecret(&ourKeys.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ourShared[:], theirShared[:]) != 0 {
		t.Fatal("Shared secrets don't match")
	}
}
