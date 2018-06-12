package network

import (
	"net"

	"github.com/jamesbcook/chatbot-external-api/api"
)

//Dial network connection
func Dial(network, address string) (*Session, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	s := &Session{connection: conn}
	dh, err := keyRatchet()
	if err != nil {
		return nil, err
	}
	if err := dh.CreateKeys(); err != nil {
		return nil, err
	}
	s.Keys.OurEphemeral = dh
	keyInfo := &api.KeyExchange{}
	keyInfo.ID = api.MessageID_ECDH
	keyInfo.Key = dh.PublicKey[:]
	keyInfo.IdentityKey = secretKey.PublicKey[:]

	if err := s.SendDH(keyInfo); err != nil {
		return nil, err
	}
	cDH, err := s.ReceiveDH()
	if err != nil {
		return nil, err
	}
	copy(s.Keys.TheirIdentityKey[:], cDH.IdentityKey[:])
	copy(s.Keys.Theirephemeral[:], cDH.Key[:])
	return s, nil
}
