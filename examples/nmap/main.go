package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"strings"

	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/filesystem"
	"github.com/jamesbcook/chatbot-external-api/network"
)

const (
	application = "nmap"
)

var (
	debugging   bool
	debugOutput io.Writer
)

func debug(output string) {
	if debugging {
		debugOutput.Write([]byte(output + "\n"))
	}
}

func handle(session *network.Session) {
	if len(network.GetAuthKeys()) > 0 {
		debug(fmt.Sprintf("Checking if key %v is authorized", session.Keys.TheirIdentityKey[:]))
		if !network.AuthorizedKey(session.Keys.TheirIdentityKey[:]) {
			session.Close()
			return
		}
	}
	for {
		debug("Getting Encrypted Message")
		msg, err := session.ReceiveEncryptedMsg()
		if err != nil {
			log.Println(err)
			session.Close()
			return
		}
		switch msg.ID {
		case api.MessageID_Nmap:
			debug(fmt.Sprintf("Scanning with the following arguments %s", msg.IO))
			var res []byte
			res, err = scan(msg.IO)
			if err != nil {
				temp := fmt.Sprintf("Error scanning %v", err)
				res = []byte(temp)
			}
			m := &api.Message{}
			m.ID = api.MessageID_Response
			m.IO = []byte(res)
			debug(fmt.Sprintf("Sending message back to session: %v", m))
			if err := session.SendEncryptedMsg(m); err != nil {
				log.Println(err)
				return
			}
		case api.MessageID_Hash:
			fmt.Println("Not Implemented")
		case api.MessageID_Done:
			debug("Closing session")
			session.Close()
			return
		}
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

func main() {
	lport := flag.String("lport", "9292", "Port to listen on")
	validKeys := flag.String("keys", "", "File of authorized keys")
	debugFlag := flag.Bool("debug", false, "Print debug info")
	flag.Parse()
	debugOutput = os.Stdout
	debugging = *debugFlag
	l, err := network.Listen("tcp", ":"+*lport)
	if err != nil {
		log.Fatal(err)
	}
	var file string
	if *validKeys == "" {
		fs, err := filesystem.New(application)
		if err != nil {
			log.Println(err)
		}
		file = fs.GetAuthorizedKeyFile()
		if err != nil {
			log.Println(err)
		}
	} else {
		file = *validKeys
	}
	debug(fmt.Sprintf("File name %s", file))
	output, err := ioutil.ReadFile(file)
	if err != nil {
		log.Println(err)
	}
	debug(fmt.Sprintf("File output length %d", len(output)))
	if len(output) > 0 {
		for _, key := range strings.Split(string(output), "\n") {
			if key == "" {
				continue
			}
			decodeKey, err := hex.DecodeString(key)
			if err != nil {
				log.Fatal(err)
			}
			network.AddAuthKey(decodeKey)
			debug(fmt.Sprintf("Adding key string: %s\nbyte array: %v", key, decodeKey))
		}
	}
	defer l.Close()
	for {
		s, err := l.Accept()
		if err != nil {
			log.Println(err)
			continue
		}
		debug("Got a connection")
		go handle(s)
	}
}
