package crypto

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/curve25519"
)

//ECDH key holder
type ECDH struct {
	PrivateKey *memguard.LockedBuffer
	PublicKey  *memguard.LockedBuffer
}

//CreateKeys for ecdh algo to perform dh key exchange
func (ecdh *ECDH) CreateKeys() error {
	pkG, err := memguard.NewMutable(32)
	if err != nil {
		return fmt.Errorf("Error guarding memory %v", err)
	}
	skG, err := memguard.NewMutable(32)
	if err != nil {
		return fmt.Errorf("Error guarding memory %v", err)
	}
	pk := pkG.BufferPointer32()
	sk := skG.BufferPointer32()
	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return fmt.Errorf("couldn't generate privKey: %s", err)
	}
	sk[0] &= 248
	sk[31] &= 127
	sk[31] |= 64
	curve25519.ScalarBaseMult(pk, sk)
	ecdh.PrivateKey = skG
	ecdh.PublicKey = pkG
	if err := ecdh.PrivateKey.MakeImmutable(); err != nil {
		return fmt.Errorf("Error making private key memory immutable")
	}
	if err := ecdh.PublicKey.MakeImmutable(); err != nil {
		return fmt.Errorf("Error making public key memory immutable")
	}
	return nil
}

//GenerateSharedSecret based on the public key of the user we are talking to
func (ecdh *ECDH) GenerateSharedSecret(theirPK *[32]byte) (*memguard.LockedBuffer, error) {
	output, err := memguard.NewMutable(32)
	if err != nil {
		return nil, fmt.Errorf("Error guarding memory %v", err)
	}
	curve25519.ScalarMult(output.BufferPointer32(), ecdh.PrivateKey.BufferPointer32(), theirPK)
	if err := output.MakeImmutable(); err != nil {
		return nil, fmt.Errorf("Error making public key memory immutable")
	}
	return output, nil
}
