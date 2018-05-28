package network

import (
	"encoding/binary"
	"fmt"

	proto "github.com/golang/protobuf/proto"
	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/crypto"
)

//SendDH to a connection
func (s Session) SendDH(keyInfo *api.KeyExchange) error {
	marshaledKey, err := proto.Marshal(keyInfo)
	if err != nil {
		return fmt.Errorf("Error marshaling key %v", err)
	}
	marshLen := uint32(len(marshaledKey))
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, marshLen)
	fullKeyMsg := make([]byte, 4+marshLen)
	copy(fullKeyMsg, lenBuf)
	copy(fullKeyMsg[4:], marshaledKey)

	if _, err := s.connection.Write(fullKeyMsg); err != nil {
		return fmt.Errorf("Error sending dh key %v", err)
	}
	return nil
}

func (s Session) ReceiveDH() (*api.KeyExchange, error) {
	msgLength := make([]byte, 4)
	_, err := s.connection.Read(msgLength)
	if err != nil {
		return nil, fmt.Errorf("Error reading length message %v", err)
	}
	length := binary.LittleEndian.Uint32(msgLength)
	msg := make([]byte, length)
	if _, err := s.connection.Read(msg); err != nil {
		return nil, fmt.Errorf("Error reading key %v", err)
	}
	keyExchange := &api.KeyExchange{}
	err = proto.Unmarshal(msg, keyExchange)
	if err != nil {
		return nil, err
	}
	if !crypto.Verify(keyExchange.IdentityKey, keyExchange.Key, keyExchange.Signature) {
		return nil, fmt.Errorf("Signature doesn't match")
	}
	fmt.Println("Keys valid")
	return keyExchange, nil
}
