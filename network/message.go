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
	var tmpsKey [32]byte
	copy(tmpsKey[:], s.Keys.Theirephemeral)
	sessionCrypto.Key, err = s.Keys.OurEphemeral.GenerateSharedSecret(&tmpsKey)
	if err != nil {
		return err
	}
	s.Keys.OurEphemeral.PrivateKey.Wipe()
	s.Keys.OurEphemeral.PublicKey.Wipe()
	if err := sessionCrypto.CreateKey(nil); err != nil {
		return err
	}
	dh, err := keyRatchet()
	if err != nil {
		return err
	}
	s.Keys.OurEphemeral = dh
	message.NextKey = dh.PublicKey.Buffer()
	message.Signature = secretKey.Sign(dh.PublicKey.Buffer())
	marshalled, err := proto.Marshal(message)
	if err != nil {
		return err
	}
	encryptedOut, err := sessionCrypto.Encrypt(marshalled)
	if err != nil {
		return err
	}
	sessionCrypto.Key.Destroy()
	lengthBuffer := make([]byte, 4)
	msgLength := uint32(len(encryptedOut))
	binary.LittleEndian.PutUint32(lengthBuffer, msgLength+12)
	fullSessionMessage := make([]byte, 4+12+msgLength)
	copy(fullSessionMessage, lengthBuffer)
	copy(fullSessionMessage[4:], sessionCrypto.Nonce[:])
	copy(fullSessionMessage[4+12:], encryptedOut)
	if _, err := s.connection.Write(fullSessionMessage); err != nil {
		return fmt.Errorf("Error sending encrypted message %v", err)
	}
	return nil
}

//ReceiveEncryptedMsg from a connection
func (s *Session) ReceiveEncryptedMsg() (*api.Message, error) {
	sLen := make([]byte, 4)
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
	sessionCrypto := &crypto.Symmetric{}
	var nonce [12]byte
	var tmpsKey [32]byte
	copy(tmpsKey[:], s.Keys.Theirephemeral)
	sessionCrypto.Key, err = s.Keys.OurEphemeral.GenerateSharedSecret(&tmpsKey)
	if err != nil {
		return nil, err
	}
	//s.Keys.OurEphemeral.PrivateKey.Wipe()
	//s.Keys.OurEphemeral.PublicKey.Wipe()
	copy(nonce[:], payload[0:12])
	if err := sessionCrypto.CreateKey(&nonce); err != nil {
		return nil, err
	}
	output, err := sessionCrypto.Decrypt(payload[12:])
	if err != nil {
		return nil, err
	}
	sessionCrypto.Key.Destroy()
	ms := &api.Message{}
	err = proto.Unmarshal(output, ms)
	if err != nil {
		return nil, err
	}
	if !crypto.Verify(s.Keys.TheirIdentityKey, ms.NextKey, ms.Signature) {
		return nil, fmt.Errorf("Sig doesn't match")
	}
	s.Keys.Theirephemeral = ms.NextKey
	return ms, nil
}
