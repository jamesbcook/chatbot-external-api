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

type Session struct {
	connection net.Conn
	Keys       keys
}

type Listener struct {
	listener net.Listener
}

func init() {
	if err := secretKey.CreateKeys(); err != nil {
		log.Fatal(err)
	}
}

func SetSecretKeyPair(key crypto.ED25519) {
	secretKey = key
}

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

func (s *Session) Close() error {
	return s.connection.Close()
}
