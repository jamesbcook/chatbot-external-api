package network

import (
	"bytes"

	"github.com/jamesbcook/chatbot-external-api/crypto"
	"golang.org/x/crypto/sha3"
)

var (
	validKeys = [][]byte{}
)

func hashMessage(msg []byte) []byte {
	sha := sha3.New256()
	sha.Write(msg)
	return sha.Sum(nil)
}

func signMessage(msg []byte) []byte {
	return secretKey.Sign(msg)
}

func verifyMessage(pk, msg []byte) bool {
	signature := make([]byte, signatureSize)
	copy(signature, msg[0:64])
	return crypto.Verify(pk, hashMessage(msg[64:]), signature)
}

//AddAuthKey to array of keys
func AddAuthKey(key []byte) {
	validKeys = append(validKeys, key)
}

//GetAuthKeys currently stored
func GetAuthKeys() [][]byte {
	return validKeys
}

//AuthorizedKey returns if the given key is accepted or not
func AuthorizedKey(givenKey []byte) bool {
	for _, key := range validKeys {
		if bytes.Compare(key, givenKey) == 0 {
			return true
		}
	}
	return false
}
