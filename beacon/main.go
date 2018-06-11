package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/jamesbcook/chatbot-external-api/api"
	"github.com/jamesbcook/chatbot-external-api/network"
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

func saveKeys() {
	log.Println("Saving public key to key.pub")
	if err := ioutil.WriteFile("key.pub", []byte(network.GetIdentityKey()), 0660); err != nil {
		log.Println("Couldn't write public key to file")
	}
	log.Println("Saving private key to key.priv")
	if err := ioutil.WriteFile("key.priv", []byte(network.GetSecretKey()), 0660); err != nil {
		log.Println("Couldn't write private key to file")
	}
}

func loadFile(file string) ([]byte, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	fileData, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	output := make([]byte, hex.DecodedLen(len(fileData)))
	_, err = hex.Decode(output, fileData)
	if err != nil {
		return nil, err
	}
	return output, nil
}

func keySetup(privFlag, pubFlag string) error {
	pub, err := loadFile(pubFlag)
	if err != nil {
		return fmt.Errorf("Couldn't load %s", pubFlag)
	}
	priv, err := loadFile(privFlag)
	if err != nil {
		return fmt.Errorf("Couldn't load %s", privFlag)
	}
	if err := network.SetSecretKeyPair(priv, pub); err != nil {
		return fmt.Errorf("Couldn't set key pair, using random key")
	}
	return nil
}

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	lPort := flag.Int("lport", 50001, "Local port to listen on")
	rhost := flag.String("rhost", "localhost:55449", "Host to send messages to")
	pub := flag.String("pub", "./key.pub", "Public Key File")
	private := flag.String("private", "./key.priv", "Private Key File")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "beacon %v by %s \nUsage:\n", "1.0.0", "@_jbcook")
		flag.PrintDefaults()
	}
	flag.Parse()
	if err := keySetup(*private, *pub); err != nil {
		log.Println(err)
		saveKeys()
	}
	fmt.Printf("Loaded Public Key %s\n", network.GetIdentityKey())
	httpListen := fmt.Sprintf(":%d", *lPort)
	remoteHost = *rhost
	http.HandleFunc("/", csHandler)
	if err := http.ListenAndServe(httpListen, nil); err != nil {
		log.Fatal(err)
	}
}
