package network_test

import (
	"os"
	"testing"
	"time"

	"github.com/jamesbcook/chatbot-external-api/network"
)

var (
	address = os.Getenv("CHATBOT_TEST_ADDRESS")
)

func TestDial(t *testing.T) {
	address := "localhost:8080"
	go func() {
		l, err := network.Listen("tcp", address)
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
	s, err := network.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}
