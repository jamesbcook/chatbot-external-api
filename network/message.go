package network

import (
	"encoding/binary"
	"fmt"

	proto "github.com/golang/protobuf/proto"
	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/crypto"
)

//SendEncryptedMsg to a connection
func (s *Session) SendEncryptedMsg(message *api.Message) error {
	var err error
	sessionCrypto := &crypto.Symmetric{}
	var tmpKey [32]byte
	copy(tmpKey[:], s.Keys.Theirephemeral[:])
	sessionCrypto.Key, err = s.Keys.OurEphemeral.GenerateSharedSecret(&tmpKey)
	if err != nil {
		return err
	}
	if err := sessionCrypto.CreateKey(nil); err != nil {
		return err
	}
	dh, err := keyRatchet()
	if err != nil {
		return err
	}
	s.Keys.OurEphemeral = dh
	randomPadding, err := getRandomPading(128)
	if err != nil {
		return err
	}
	message.RandomPadding = randomPadding
	message.NextKey = dh.PublicKey[:]
	marshalled, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	encryptedOut, err := sessionCrypto.Encrypt(marshalled)
	if err != nil {
		return err
	}

	var signData []byte
	signData = append(signData, sessionCrypto.Nonce[:]...)
	signData = append(signData, encryptedOut...)
	signed := signMessage(hashMessage(signData))
	lengthBuffer := make([]byte, msgLengthSize)
	msgLength := uint32(len(encryptedOut))
	binary.LittleEndian.PutUint32(lengthBuffer, signatureSize+nonceLengthSize+msgLength)
	fullSessionMessage := make([]byte, msgLengthSize+signatureSize+nonceLengthSize+msgLength)
	copy(fullSessionMessage, lengthBuffer)
	copy(fullSessionMessage[msgLengthSize:], signed)
	copy(fullSessionMessage[msgLengthSize+signatureSize:], sessionCrypto.Nonce[:])
	copy(fullSessionMessage[msgLengthSize+signatureSize+nonceLengthSize:], encryptedOut)
	if _, err := s.connection.Write(fullSessionMessage); err != nil {
		return fmt.Errorf("Error sending encrypted message %v", err)
	}
	return nil
}

//ReceiveEncryptedMsg from a connection
func (s *Session) ReceiveEncryptedMsg() (*api.Message, error) {
	sLen := make([]byte, msgLengthSize)
	_, err := s.connection.Read(sLen)
	if err != nil {
		return nil, fmt.Errorf("Error reading encrypted msg length %v", err)
	}
	payloadLength := binary.LittleEndian.Uint32(sLen)
	payload := make([]byte, payloadLength)
	_, err = s.connection.Read(payload)
	if err != nil {
		return nil, fmt.Errorf("Error reading encrypted msg length %v", err)
	}
	if !verifyMessage(s.Keys.TheirIdentityKey[:], payload) {
		return nil, fmt.Errorf("Message sig not valid")
	}
	sessionCrypto := &crypto.Symmetric{}
	var nonce [12]byte
	var tmpKey [32]byte
	copy(tmpKey[:], s.Keys.Theirephemeral[:])
	sessionCrypto.Key, err = s.Keys.OurEphemeral.GenerateSharedSecret(&tmpKey)
	if err != nil {
		return nil, err
	}
	copy(nonce[:], payload[64:76])
	if err := sessionCrypto.CreateKey(&nonce); err != nil {
		return nil, err
	}
	output, err := sessionCrypto.Decrypt(payload[76:])
	if err != nil {
		return nil, err
	}

	ms := &api.Message{}
	err = proto.Unmarshal(output, ms)
	if err != nil {
		return nil, err
	}
	copy(s.Keys.Theirephemeral[:], ms.NextKey[:])
	return ms, nil
}
