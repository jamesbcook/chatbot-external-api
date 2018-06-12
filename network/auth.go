package network

import (
	"bytes"

	"github.com/jamesbcook/chatbot-external-api/crypto"
	"golang.org/x/crypto/sha3"
)

var (
	validKeys = [][]byte{}
)

func signMessage(msg []byte) []byte {
	sha := sha3.New256()
	return secretKey.Sign(sha.Sum(msg))
}

func verifyMessage(pk, msg []byte) bool {
	signature := make([]byte, signatureSize)
	copy(signature, msg[0:64])
	sha := sha3.New256()
	return crypto.Verify(pk, sha.Sum(msg[64:]), signature)
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
