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

func saveKeys(skFile, pkFile string) error {
	log.Printf("Saving public key to %s", pkFile)
	if err := ioutil.WriteFile(pkFile, []byte(network.GetIdentityKey()), 0400); err != nil {
		return fmt.Errorf("Couldn't write public key to file")
	}
	log.Printf("Saving private key to %s", skFile)
	if err := ioutil.WriteFile(skFile, []byte(network.GetSecretKey()), 0400); err != nil {
		return fmt.Errorf("Couldn't write private key to file")
	}
	return nil
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
	pub := flag.String("pub", "", "Public Key File")
	private := flag.String("private", "", "Private Key File")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "beacon %v by %s \nUsage:\n", "1.0.0", "@_jbcook")
		flag.PrintDefaults()
	}
	flag.Parse()
	sf, err := filesystem.GetPrivateKeyFile(app)
	if err != nil {
		log.Fatal(err)
	}
	pf, err := filesystem.GetPublicKeyFile(app)
	if err != nil {
		log.Fatal(err)
	}
	if *pub == "" || *private == "" {
		if err := keySetup(sf, pf); err != nil {
			log.Println(err)
			if err := saveKeys(sf, pf); err != nil {
				log.Fatal(err)
			}
		}
	} else {
		if err := keySetup(*private, *pub); err != nil {
			log.Println(err)
			if err := saveKeys(sf, pf); err != nil {
				log.Fatal(err)
			}
		}
	}
	fmt.Printf("Loaded Public Key %s\n", network.GetIdentityKey())
	httpListen := fmt.Sprintf(":%d", *lPort)
	remoteHost = *rhost
	http.HandleFunc("/", csHandler)
	if err := http.ListenAndServe(httpListen, nil); err != nil {
		log.Fatal(err)
	}
}
