package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/filesystem"
	"github.com/jamesbcook/chatbot-external-api/network"
)

const (
	app = "beacon"
)

var (
	remoteHost string
)

func csHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		log.Println(err)
		return
	}

	msg := &api.Message{}
	msg.ID = api.MessageID_Beacon
	msg.IO = []byte(r.FormValue("content"))
	msg.Channel = r.FormValue("channel")
	s, err := network.Dial("tcp", remoteHost)
	if err != nil {
		log.Println(err)
		return
	}
	if err := s.SendEncryptedMsg(msg); err != nil {
		log.Println(err)
		return
	}
	if _, err := s.ReceiveEncryptedMsg(); err != nil {
		log.Println(err)
		return
	}
	msg.ID = api.MessageID_Done
	length := rand.Intn(48)
	buf := make([]byte, length)
	rand.Read(buf)
	msg.IO = buf
	if err := s.SendEncryptedMsg(msg); err != nil {
		log.Println(err)
		return
	}
	if err := s.Close(); err != nil {
		log.Println(err)
		return
	}

	w.WriteHeader(200)
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	lPort := flag.Int("lport", 50001, "Local port to listen on")
	rhost := flag.String("rhost", "localhost:55449", "Host to send messages to")
	pub := flag.String("pub", "", "Public Key File")
	private := flag.String("private", "", "Private Key File")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "beacon %v by %s \nUsage:\n", "1.0.0", "@_jbcook")
		flag.PrintDefaults()
	}
	flag.Parse()

	var privBytes [64]byte
	var pubBytes [32]byte

	if *pub == "" || *private == "" {
		fs, err := filesystem.New(app)
		if err != nil {
			log.Fatal(err)
		}
		sk, err := fs.LoadPrivateKeyFile()
		if err != nil {
			log.Fatal(err)
		}
		pk, err := fs.LoadPublicKeyFile()
		if err != nil {
			log.Fatal(err)
		}
		copy(privBytes[:], sk)
		copy(pubBytes[:], pk)
	} else {
		sk, err := filesystem.LoadFile(*private)
		if err != nil {
			log.Fatal(err)
		}
		pk, err := filesystem.LoadFile(*pub)
		if err != nil {
			log.Fatal(err)
		}
		copy(privBytes[:], sk)
		copy(pubBytes[:], pk)
	}
	if err := network.SetSecretKeyPair(privBytes[:], pubBytes[:]); err != nil {
		log.Fatal("Couldn't set key pair, using random key")
	}
	fmt.Printf("Loaded Public Key %s\n", network.GetIdentityKey())
	httpListen := fmt.Sprintf(":%d", *lPort)
	remoteHost = *rhost
	http.HandleFunc("/", csHandler)
	if err := http.ListenAndServe(httpListen, nil); err != nil {
		log.Fatal(err)
	}
}
