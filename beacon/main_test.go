package main

import (
	"os"
	"testing"

	"github.com/jamesbcook/chatbot-external-api/filesystem"
)

func TestKeySetup(t *testing.T) {
	sf, err := filesystem.GetPrivateKeyFile(app)
	if err != nil {
		t.Fatal(err)
	}
	pf, err := filesystem.GetPublicKeyFile(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := keySetup("asdfa", "adsfasdf"); err == nil {
		t.Fatal("This should have failed")
	}
	if err := keySetup(sf, pf); err != nil {
		t.Fatal("This should not have failed")
	}
}

func TestLoadFile(t *testing.T) {
	pf, err := filesystem.GetPublicKeyFile(app)
	if err != nil {
		t.Fatal(err)
	}
	output, err := loadFile(pf)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) <= 0 {
		t.Fatal("Zero length output")
	}
	t.Log(string(output))
}

func TestSaveKeys(t *testing.T) {
	directory := "./.testing/"
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	if err := saveKeys(directory+"priv.key", directory+"pub.key"); err != nil {
		t.Fatal(err)
	}
	if err := saveKeys("asdfasdf/"+"priv.key", "asdfasdf/"+"pub.key"); err == nil {
		t.Fatal("this should have failed")
	}
	if err := os.RemoveAll(directory); err != nil {
		t.Fatal(err)
	}
}
