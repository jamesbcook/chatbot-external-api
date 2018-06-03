package crypto

import (
	"fmt"

	"github.com/awnumar/memguard"
	"golang.org/x/crypto/ed25519"
)

//ED25519 key holder
type ED25519 struct {
	PrivateKey *memguard.LockedBuffer
	PublicKey  *memguard.LockedBuffer
}

//CreateKeys generates a random keypair for ed25519 algorithm to sign and verify messages
func (ed *ED25519) CreateKeys() error {
	pkG, err := memguard.NewMutable(32)
	if err != nil {
		return fmt.Errorf("Error guarding memory %v", err)
	}
	skG, err := memguard.NewMutable(64)
	if err != nil {
		return fmt.Errorf("Error guarding memory %v", err)
	}

	err = ed25519.SecureGenerateKey(pkG.BufferPointer(), skG.BufferPointer(), nil)

	ed.PrivateKey = skG
	ed.PublicKey = pkG

	if err := ed.PrivateKey.MakeImmutable(); err != nil {
		return fmt.Errorf("Error making private key memory immutable")
	}
	if err := ed.PublicKey.MakeImmutable(); err != nil {
		return fmt.Errorf("Error making public key memory immutable")
	}

	return nil
}

//SetKeys for ed25519 algorithm to sign and verify messages
func SetKeys(private, public []byte) (*ED25519, error) {
	ed := &ED25519{}
	pkG, err := memguard.NewMutable(32)
	if err != nil {
		return nil, fmt.Errorf("Error guarding memory %v", err)
	}
	skG, err := memguard.NewMutable(64)
	if err != nil {
		return nil, fmt.Errorf("Error guarding memory %v", err)
	}
	if err := pkG.Copy(public); err != nil {
		return nil, err
	}
	if err := skG.Copy(private); err != nil {
		return nil, err
	}
	ed.PrivateKey = skG
	ed.PublicKey = pkG

	if err := ed.PrivateKey.MakeImmutable(); err != nil {
		return nil, fmt.Errorf("Error making private key memory immutable")
	}
	if err := ed.PublicKey.MakeImmutable(); err != nil {
		return nil, fmt.Errorf("Error making public key memory immutable")
	}
	return ed, nil
}

//Sign message with ed25519 private key
func (ed *ED25519) Sign(message []byte) []byte {
	return ed25519.Sign(ed.PrivateKey.Buffer(), message)
}

//Verify message with the senders public key
func Verify(pk, message, sig []byte) bool {
	return ed25519.Verify(pk, message, sig)
}
