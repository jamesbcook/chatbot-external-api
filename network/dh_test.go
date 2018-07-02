package network_test

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"
	"time"

	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/network"
)

func TestSendDH(t *testing.T) {
	var l *network.Listener
	var err error
	go func() {
		l, err = network.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		s, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	time.Sleep(2 * time.Second)
	s, err := network.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := hex.DecodeString(network.GetIdentityKey())
	if err != nil {
		t.Fatal(err)
	}
	var fakeKey [32]byte
	_, err = io.ReadFull(rand.Reader, fakeKey[:])
	if err != nil {
		t.Fatal(err)
	}
	keyInfo := &api.KeyExchange{}
	keyInfo.ID = api.MessageID_ECDH
	keyInfo.Key = fakeKey[:]
	keyInfo.IdentityKey = pubKey
	if err := s.SendDH(keyInfo); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveDH(t *testing.T) {
	var l *network.Listener
	var err error
	go func() {
		l, err = network.Listen("tcp", "localhost:0")
		if err != nil {
			t.Fatal(err)
		}
		s, err := l.Accept()
		if err != nil {
			t.Fatal(err)
		}
		keyInfo, err := s.ReceiveDH()
		if err != nil {
			t.Fatal(err)
		}
		if keyInfo.ID != api.MessageID_ECDH {
			t.Fatal("key id did not match")
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	}()
	time.Sleep(2 * time.Second)
	s, err := network.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	pubKey, err := hex.DecodeString(network.GetIdentityKey())
	if err != nil {
		t.Fatal(err)
	}
	var fakeKey [32]byte
	_, err = io.ReadFull(rand.Reader, fakeKey[:])
	if err != nil {
		t.Fatal(err)
	}
	keyInfo := &api.KeyExchange{}
	keyInfo.ID = api.MessageID_ECDH
	keyInfo.Key = fakeKey[:]
	keyInfo.IdentityKey = pubKey
	if err := s.SendDH(keyInfo); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
