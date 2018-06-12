package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

//Symmetric key holder
type Symmetric struct {
	Key   [32]byte
	Nonce [12]byte
	aead  cipher.AEAD
}

//CreateKey for symmetric encryption
func (symmetric *Symmetric) CreateKey(nonce *[12]byte) error {
	block, err := aes.NewCipher(symmetric.Key[:])
	if err != nil {
		return fmt.Errorf("error creating cipher %v", err.Error())
	}

	var tmpNonce [12]byte
	if nonce == nil {
		// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
		if _, err := io.ReadFull(rand.Reader, tmpNonce[:]); err != nil {
			return fmt.Errorf("error writing to nonce %v", err.Error())
		}
	} else {
		copy(tmpNonce[:], nonce[:])
	}

	symmetric.Nonce = tmpNonce

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("error creating new gcm %v", err.Error())
	}
	symmetric.aead = aesgcm
	return nil
}

//Encrypt data with a symmetric key
func (symmetric *Symmetric) Encrypt(data []byte) ([]byte, error) {
	return symmetric.aead.Seal(nil, symmetric.Nonce[:], data, nil), nil
}

//Decrypt Data with a symmetric key
func (symmetric *Symmetric) Decrypt(data []byte) ([]byte, error) {
	plaintext, err := symmetric.aead.Open(nil, symmetric.Nonce[:], data, nil)
	if err != nil {
		return nil, fmt.Errorf("Error decrypting message %v", err)
	}
	return plaintext, nil
}
