package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

//ECDH key holder
type ECDH struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

//CreateKeys for ecdh algorithm to perform dh key exchange
func (ecdh *ECDH) CreateKeys() error {

	if _, err := io.ReadFull(rand.Reader, ecdh.PrivateKey[:]); err != nil {
		return fmt.Errorf("couldn't generate private key: %s", err)
	}
	ecdh.PrivateKey[0] &= 248
	ecdh.PrivateKey[31] &= 127
	ecdh.PrivateKey[31] |= 64
	curve25519.ScalarBaseMult(&ecdh.PublicKey, &ecdh.PrivateKey)

	return nil
}

//GenerateSharedSecret based on the public key of the user we are talking to
func (ecdh *ECDH) GenerateSharedSecret(theirPK *[32]byte) ([32]byte, error) {
	var output [32]byte

	curve25519.ScalarMult(&output, &ecdh.PrivateKey, theirPK)

	return output, nil
}
