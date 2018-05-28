package network

import (
	"encoding/hex"
	"log"
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
	Theirephemeral   []byte
	TheirIdentityKey []byte
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
func SetSecretKeyPair(key crypto.ED25519) {
	secretKey = key
}

//GetIdentityKey returns the public key of your ed25519 key pair
func GetIdentityKey() string {
	return hex.EncodeToString(secretKey.PrivateKey.Buffer())
}

func keyRatchet() (*crypto.ECDH, error) {
	dhKey := &crypto.ECDH{}
	if err := dhKey.CreateKeys(); err != nil {
		return nil, err
	}
	return dhKey, nil
}

//Close session connection
func (s *Session) Close() error {
	return s.connection.Close()
}
