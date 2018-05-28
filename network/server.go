package network

import (
	"fmt"
	"net"

	"github.com/jamesbcook/chatbot-external-api/api"
)

func (l *Listener) Close() error {
	return l.listener.Close()
}

func (l Listener) Addr() net.Addr {
	return l.listener.Addr()
}

func Listen(network, address string) (*Listener, error) {
	extAPI := &Listener{}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	extAPI.listener = l
	return extAPI, nil
}

func (l Listener) Accept() (*Session, error) {
	conn, err := l.listener.Accept()
	if err != nil {
		return nil, err
	}
	fmt.Println("Got a connection")
	s := &Session{connection: conn}
	key, err := s.ReceiveDH()
	if err != nil {
		return nil, err
	}
	s.Keys.TheirIdentityKey = key.IdentityKey
	s.Keys.Theirephemeral = key.Key
	ourDH, err := keyRatchet()
	if err != nil {
		return nil, err
	}
	s.Keys.OurEphemeral = ourDH
	signedDHKey := secretKey.Sign(ourDH.PublicKey.Buffer())
	keyInfo := &api.KeyExchange{}
	keyInfo.ID = api.MessageID_ECDH
	keyInfo.IdentityKey = secretKey.PublicKey.Buffer()
	keyInfo.Key = ourDH.PublicKey.Buffer()
	keyInfo.Signature = signedDHKey
	if err := s.SendDH(keyInfo); err != nil {
		return nil, err
	}
	return s, nil
}
