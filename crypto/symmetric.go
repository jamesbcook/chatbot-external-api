package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/argon2"
)

//Symmetric key holder
type Symmetric struct {
	Key   [32]byte
	Nonce [12]byte
	salt  [32]byte //salt for when a user creates a key with a password
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
		if _, err := rand.Read(tmpNonce[:]); err != nil {
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

//KeyFromPassword takes a password from a user and expands it with argon2. The symmetric struct will be populated with a 32 byte key. The nonce is to be filled by the user as it is set to 12 bytes of 0's
func (symmetric *Symmetric) KeyFromPassword(password []byte, salt *[32]byte) error {
	ourSalt := make([]byte, 32)
	if salt == nil {
		if _, err := rand.Read(ourSalt); err != nil {
			return err
		}
	} else {
		copy(ourSalt, (*salt)[:])
	}
	key := argon2.Key(password, ourSalt, 3, 32*1024, 4, 32)
	nonce := [12]byte{0}
	copy(symmetric.Key[:], key)
	copy(symmetric.salt[:], ourSalt)
	copy(symmetric.Nonce[:], nonce[:])
	symmetric.CreateKey(nil)
	return nil
}

//GenerateNonce of 12 bytes from a random source
func GenerateNonce() (*[12]byte, error) {
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	return &nonce, nil
}

//GetPasswordSalt returns the salt used during the scrypt key expansion process
func (symmetric Symmetric) GetPasswordSalt() [32]byte {
	return symmetric.salt
}
