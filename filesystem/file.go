package filesystem

import (
	"fmt"
	"os"
)

func getKeyDirectory() string {
	return fmt.Sprintf("%s/%s/", os.Getenv("HOME"), ".chatbot")
}

func mkdir(application string) error {
	directory := fmt.Sprintf(getKeyDirectory()+"%s", application)
	return os.MkdirAll(directory, 0700)
}

//GetPublicKeyFile for the passed in application
func GetPublicKeyFile(application string) (string, error) {
	err := mkdir(application)
	return fmt.Sprintf(getKeyDirectory()+"%s/pub.key", application), err

}

//GetPrivateKeyFile for the passed in application
func GetPrivateKeyFile(application string) (string, error) {
	err := mkdir(application)
	return fmt.Sprintf(getKeyDirectory()+"%s/priv.key", application), err
}
