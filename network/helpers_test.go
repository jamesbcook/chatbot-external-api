package network

import (
	"bytes"
	"encoding/hex"
	"log"
	"testing"
)

func TestSetSecretKeyPair(t *testing.T) {
	priv, err := hex.DecodeString("4a432aff63c807241f107d8615e8bf051e03e9492be22a1321d046c5bba2cdcc7bb61e895ada9a1310598d6ebfee61a04c8e3995add57e0babc1e2c6e37aa417")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString("7bb61e895ada9a1310598d6ebfee61a04c8e3995add57e0babc1e2c6e37aa417")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetSecretKeyPair(priv, pub); err != nil {
		t.Fatal(err)
	}
}

func TestGenerateSecretKeyPair(t *testing.T) {
	if err := GenerateSecretKeyPair(); err != nil {
		t.Fatal(err)
	}
}

func TestGetIdentityKey(t *testing.T) {
	expected := "7bb61e895ada9a1310598d6ebfee61a04c8e3995add57e0babc1e2c6e37aa417"
	setTestKeys(t)
	if GetIdentityKey() != expected {
		t.Fatal("Identity Key does not match")
	}
}

func TestGetSecretKey(t *testing.T) {
	expected := "4a432aff63c807241f107d8615e8bf051e03e9492be22a1321d046c5bba2cdcc7bb61e895ada9a1310598d6ebfee61a04c8e3995add57e0babc1e2c6e37aa417"
	setTestKeys(t)
	if GetSecretKey() != expected {
		t.Fatal("Secret Key does not match")
	}
}

func TestKeyRatchet(t *testing.T) {
	ecdh, err := keyRatchet()
	if err != nil {
		t.Fatal(err)
	}
	zeroed := [32]byte{0}
	if bytes.Compare(ecdh.PrivateKey[:], zeroed[:]) == 0 {
		log.Fatal("Private key was empty")
	}
	if bytes.Compare(ecdh.PublicKey[:], zeroed[:]) == 0 {
		log.Fatal("Public key was empty")
	}
}
