package main

import (
	"fmt"
	"log"
	"os/exec"
	"strings"

	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/network"
)

func main() {
	fmt.Println("Server")
	l, err := network.Listen("tcp", ":9292")
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()
	for {
		s, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		defer s.Close()
		go func(sess *network.Session) {
			for {
				msg, err := sess.ReceiveEncryptedMsg()
				if err != nil {
					log.Println(err)
					s.Close()
					return
				}
				switch msg.ID {
				case api.MessageID_Nmap:
					fmt.Println(string(msg.IO))
					var res []byte
					res, err = scan(msg.IO)
					if err != nil {
						temp := fmt.Sprintf("Error scanning %v", err)
						res = []byte(temp)
					}
					m := &api.Message{}
					m.ID = api.MessageID_Response
					m.IO = []byte(res)
					if err := sess.SendEncryptedMsg(m); err != nil {
						log.Println(err)
						return
					}
				case api.MessageID_Hash:
					fmt.Println("Not Implemented")
				case api.MessageID_Done:
					return
				}
			}
		}(s)
	}
}

func scan(args []byte) ([]byte, error) {
	cmd := exec.Command("nmap", strings.Split(string(args), " ")...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}
	return out, nil
}
