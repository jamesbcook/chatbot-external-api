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

func encodeHex(input []byte) []byte {
	output := make([]byte, hex.EncodedLen(len(input)))
	hex.Encode(output, input)
	return output
}

func decodeHex(input []byte) ([]byte, error) {
	output := make([]byte, hex.DecodedLen(len(input)))
	_, err := hex.Decode(output, input)
	if err != nil {
		return nil, err
	}
	return output, nil
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

//SaveKeyToFile based on the path passed in
func SaveKeyToFile(key []byte, path string) error {
	return ioutil.WriteFile(path, key, 0600)
}

//LoadFile returns the hex decoded contents of the passed in file
func LoadFile(file string) ([]byte, error) {
	return loadFile(file)
}

//GetPasswordSaltFile returns the salt used when creating a key from a password
func (f fs) GetPasswordSaltFile() string {
	return f.directory + "/salt"
}

//GetStateFile returns the state file
func (f fs) GetStateFile() string {
	return f.directory + "/state"
}

//WriteToFile takes a byte slice, encodes it to hex and writes that to a file new line (\n) terminated
func (f fs) WriteToFile(input []byte, path string) error {
	encodedInput := encodeHex(input)
	return ioutil.WriteFile(path, encodedInput, 0600)
}
