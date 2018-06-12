package main

import (
	"crypto/rand"
	"fmt"
	"io"
	"log"

	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/network"
)

func main() {
	fmt.Println("client")
	for x := 0; x < 100; x++ {
		s, err := network.Dial("tcp", "138.68.10.240:9292")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println("connected")
		msg := &api.Message{}
		msg.ID = api.MessageID_Nmap
		msg.IO = []byte("-sV -p 80,443,8080,22 localhost")
		if err := s.SendEncryptedMsg(msg); err != nil {
			log.Fatal(err)
		}
		recv, err := s.ReceiveEncryptedMsg()
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(recv.IO))
		msg.IO = make([]byte, 12)
		io.ReadFull(rand.Reader, msg.IO)
		msg.ID = api.MessageID_Done
		if err := s.SendEncryptedMsg(msg); err != nil {
			log.Fatal(err)
		}
		s.Close()
	}
}
