package network

import (
	"encoding/binary"
	"fmt"

	proto "github.com/golang/protobuf/proto"
	"github.com/jamesbcook/chatbot-external-api/api"
)

//SendDH to a connection
func (s Session) SendDH(keyInfo *api.KeyExchange) error {
	marshaledKey, err := proto.Marshal(keyInfo)
	if err != nil {
		return fmt.Errorf("Error marshaling key %v", err)
	}
	marshLen := uint32(len(marshaledKey))
	lenBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBuf, 64+marshLen)
	fullKeyMsg := make([]byte, 4+64+marshLen)
	signed := signMessage(marshaledKey)
	copy(fullKeyMsg, lenBuf)
	copy(fullKeyMsg[4:], signed)
	copy(fullKeyMsg[4+64:], marshaledKey)

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
	data := make([]byte, len(msg)-64)
	copy(data, msg[64:])
	keyExchange := &api.KeyExchange{}
	err = proto.Unmarshal(data, keyExchange)
	if err != nil {
		return nil, err
	}
	if !verifyMessage(keyExchange.IdentityKey, msg) {
		return nil, fmt.Errorf("Sig doesn't match")
	}
	return keyExchange, nil
}
