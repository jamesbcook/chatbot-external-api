package network_test

import (
	"testing"

	"github.com/jamesbcook/chatbot-external-api/network"
)

func TestAddr(t *testing.T) {
	l, err := network.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	if address := l.Addr(); address == nil {
		t.Fatal("address was empty")
	}
}

func TestClose(t *testing.T) {
	l, err := network.Listen("tcp", "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}
