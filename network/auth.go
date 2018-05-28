package network

import (
	"github.com/jamesbcook/chatbot-external-api/crypto"
	"golang.org/x/crypto/sha3"
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
