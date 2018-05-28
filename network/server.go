package network

import (
	"fmt"
	"net"

	"github.com/jamesbcook/chatbot-external-api/api"
)

//Close listener
func (l *Listener) Close() error {
	return l.listener.Close()
}

//Addr of your listener
func (l Listener) Addr() net.Addr {
	return l.listener.Addr()
}

//Listen for network connections
func Listen(network, address string) (*Listener, error) {
	extAPI := &Listener{}
	l, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	extAPI.listener = l
	return extAPI, nil
}

//Accept network connections
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
	keyInfo := &api.KeyExchange{}
	keyInfo.ID = api.MessageID_ECDH
	keyInfo.IdentityKey = secretKey.PublicKey.Buffer()
	keyInfo.Key = ourDH.PublicKey.Buffer()
	if err := s.SendDH(keyInfo); err != nil {
		return nil, err
	}
	return s, nil
}
