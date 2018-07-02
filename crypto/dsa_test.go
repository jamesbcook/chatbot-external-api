package crypto_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/jamesbcook/chatbot-external-api/crypto"
)

func TestCreateKeysED25519(t *testing.T) {
	ed := &crypto.ED25519{}
	if err := ed.CreateKeys(); err != nil {
		t.Fatal(err)
	}
	zeroed64 := [64]byte{0}
	zeroed32 := [32]byte{0}
	if bytes.Compare(ed.PrivateKey[:], zeroed64[:]) == 0 {
		t.Fatal("Private key wasn't filled")
	}
	if bytes.Compare(ed.PublicKey[:], zeroed32[:]) == 0 {
		t.Fatal("Public key wasn't filled")
	}
}

func TestSetKeysED25519(t *testing.T) {
	ed := &crypto.ED25519{}
	if err := ed.CreateKeys(); err != nil {
		t.Fatal(err)
	}
	setEd, err := crypto.SetKeys(ed.PrivateKey[:], ed.PublicKey[:])
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(ed.PrivateKey[:], setEd.PrivateKey[:]) != 0 {
		t.Fatal("Private keys don't match")
	}
	if bytes.Compare(ed.PublicKey[:], setEd.PublicKey[:]) != 0 {
		t.Fatal("Public keys don't match")
	}
}

func TestSignED25519(t *testing.T) {
	message := "Hello World"
	ed := &crypto.ED25519{}
	if err := ed.CreateKeys(); err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write([]byte(message))
	hashedMessage := hash.Sum(nil)
	res := ed.Sign(hashedMessage)
	if res == nil {
		t.Fatal("Results were empty")
	}
}

func TestVerifyED25519(t *testing.T) {
	message := "Hello World"
	ed := &crypto.ED25519{}
	if err := ed.CreateKeys(); err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	hash.Write([]byte(message))
	hashedMessage := hash.Sum(nil)
	res := ed.Sign(hashedMessage)
	if res == nil {
		t.Fatal("Results were empty")
	}
	if crypto.Verify(ed.PublicKey[:], hashedMessage, res) == false {
		t.Fatal("Signature is not valid")
	}
}
