package crypto

import (
	"crypto/rand"

	"golang.org/x/crypto/ed25519"
)

//ED25519 key holder
type ED25519 struct {
	PrivateKey [64]byte
	PublicKey  [32]byte
}

//CreateKeys generates a random keypair for ed25519 algorithm to sign and verify messages
func (ed *ED25519) CreateKeys() error {
	pk, sk, err := ed25519.GenerateKey(rand.Reader)

	copy(ed.PublicKey[:], pk)
	copy(ed.PrivateKey[:], sk)

	return err
}

//SetKeys for ed25519 algorithm to sign and verify messages
func SetKeys(private, public []byte) (*ED25519, error) {
	ed := &ED25519{}

	copy(ed.PrivateKey[:], private)
	copy(ed.PublicKey[:], public)

	return ed, nil
}

//Sign message with ed25519 private key
func (ed *ED25519) Sign(message []byte) []byte {
	return ed25519.Sign(ed.PrivateKey[:], message)
}

//Verify message with the senders public key
func Verify(pk, message, sig []byte) bool {
	return ed25519.Verify(pk, message, sig)
}
