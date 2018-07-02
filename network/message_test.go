package network_test

import (
	"testing"
	"time"

	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/network"
)

func TestSendEncryptedMsg(t *testing.T) {
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
	msg := &api.Message{}
	msg.ID = api.MessageID_Nmap
	msg.IO = []byte("Just Testing")
	if err := s.SendEncryptedMsg(msg); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestReceiveEncryptedMsg(t *testing.T) {
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
		msg, err := s.ReceiveEncryptedMsg()
		if err != nil {
			t.Fatal(err)
		}
		if msg.GetID() != api.MessageID_Nmap {
			t.Fatal("Message ID was wrong")
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
	msg := &api.Message{}
	msg.ID = api.MessageID_Nmap
	msg.IO = []byte("Just Testing")
	if err := s.SendEncryptedMsg(msg); err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Second)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
