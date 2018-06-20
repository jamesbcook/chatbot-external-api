package filesystem

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

type fs struct {
	directory string
}

func getKeyDirectory() string {
	return fmt.Sprintf("%s/%s/", os.Getenv("HOME"), ".chatbot")
}

func loadFile(input string) ([]byte, error) {
	f, err := os.Open(input)
	if err != nil {
		return nil, err
	}
	output, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	return decodeHex(output)
}

func decodeHex(input []byte) ([]byte, error) {
	output := make([]byte, hex.DecodedLen(len(input)))
	_, err := hex.Decode(output, input)
	if err != nil {
		return nil, err
	}
	return output, err
}

func mkdir(application string) error {
	directory := fmt.Sprintf(getKeyDirectory()+"%s", application)
	return os.MkdirAll(directory, 0700)
}

//New filesystem object
func New(application string) (*fs, error) {
	err := mkdir(application)
	if err != nil {
		return nil, err
	}
	return &fs{directory: getKeyDirectory() + application}, nil
}

//GetPublicKeyFile returns the full path to the private key file
func (f fs) GetPublicKeyFile() string {
	return f.directory + "/pub.key"
}

//GetPrivateKeyFile
func (f fs) GetPrivateKeyFile() string {
	return f.directory + "/priv.key"
}

//GetAuthorizedKeyFile for authorizing requests
func (f fs) GetAuthorizedKeyFile() string {
	return f.directory + "/authorized-keys"
}

//LoadPublicKeyFile returns the bytes of the public key file
func (f fs) LoadPublicKeyFile() ([]byte, error) {
	return loadFile(f.directory + "/pub.key")
}

//LoadPrivateKeyFile returns the bytes of the private key file
func (f fs) LoadPrivateKeyFile() ([]byte, error) {
	return loadFile(f.directory + "/priv.key")
}

func (f fs) SaveKeyToFile(key []byte, path string) error {
	return ioutil.WriteFile(path, key, 0600)
}

//LoadFile contains a hex encoded private or public key
func LoadFile(file string) ([]byte, error) {
	return loadFile(file)
}
