package network

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"math/big"
	"net"

	"github.com/jamesbcook/chatbot-external-api/crypto"
)

const (
	msgLengthSize   = 4
	nonceLengthSize = 12
	signatureSize   = 64
)

var (
	secretKey crypto.ED25519
)

type keys struct {
	OurEphemeral     *crypto.ECDH
	Theirephemeral   [32]byte
	TheirIdentityKey [32]byte
}

//Session keys
type Session struct {
	connection net.Conn
	Keys       keys
}

//Listener wrapper for server
type Listener struct {
	listener net.Listener
}

func init() {
	if err := secretKey.CreateKeys(); err != nil {
		log.Fatal(err)
	}
}

//SetSecretKeyPair for when you need a static ed25519 key pair
func SetSecretKeyPair(private, public []byte) error {
	kp, err := crypto.SetKeys(private, public)
	if err != nil {
		return err
	}
	secretKey = *kp
	return nil
}

//GenerateSecretKeyPair used as a backup if SetSecretKeyPair fails
func GenerateSecretKeyPair() error {
	return secretKey.CreateKeys()
}

//GetIdentityKey returns the public key of your ed25519 key pair
func GetIdentityKey() string {
	return hex.EncodeToString(secretKey.PublicKey[:])
}

//GetSecretKey returns the secret key of your ed25519 key pair
func GetSecretKey() string {
	return hex.EncodeToString(secretKey.PrivateKey[:])
}

func keyRatchet() (*crypto.ECDH, error) {
	dhKey := &crypto.ECDH{}
	if err := dhKey.CreateKeys(); err != nil {
		return nil, err
	}
	return dhKey, nil
}

func getRandomPading(length int64) ([]byte, error) {
	bufferLen, err := rand.Int(rand.Reader, big.NewInt(length))
	if err != nil {
		return nil, err
	}
	padding := make([]byte, bufferLen.Int64())
	_, err = rand.Read(padding)
	if err != nil {
		return nil, err
	}
	return padding, nil
}

//Close session connection
func (s *Session) Close() error {
	return s.connection.Close()
}
