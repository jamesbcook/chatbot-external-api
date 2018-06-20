package filesystem

import (
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func dirCleanup(filePath string) error {
	if _, err := os.Stat(filePath); err == nil {
		if err := os.RemoveAll(filePath); err != nil {
			return err
		}
	}
	return nil
}

func TestGetKeyDirectory(t *testing.T) {
	expected := fmt.Sprintf("%s/%s/", os.Getenv("HOME"), ".chatbot")
	got := getKeyDirectory()
	if expected != got {
		t.Fatalf("Expected %s Got %s", expected, got)
	}
}

func TestUnExportedLoadFile(t *testing.T) {
	testFile := "testing.txt"
	clear := "Hello World"
	encoded := hex.EncodeToString([]byte(clear))
	if err := ioutil.WriteFile(testFile, []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}
	output, err := loadFile(testFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != clear {
		t.Fatalf("Expected %s Got %s", clear, output)
	}
	if err := os.Remove(testFile); err != nil {
		t.Fatal(err)
	}
}

func TestDecodeHex(t *testing.T) {
	input := []byte("48656C6C6F20576F726C64")
	expected := "Hello World"
	output, err := decodeHex(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != expected {
		t.Fatalf("Expected %s Got %s", expected, output)
	}
}

func TestMKDIR(t *testing.T) {
	testDIRFull := fmt.Sprintf("%s/%s", os.Getenv("HOME"), ".chatbot/test")
	testDIR := "test"
	if err := dirCleanup(testDIRFull); err != nil {
		t.Fatal(err)
	}
	if err := mkdir(testDIR); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(testDIRFull); os.IsNotExist(err) {
		t.Fatalf("Couldn't create directory %v", err)
	}
	if err := dirCleanup(testDIRFull); err != nil {
		t.Fatal(err)
	}
}

func TestNew(t *testing.T) {
	expected := fmt.Sprintf("%s/%s", os.Getenv("HOME"), ".chatbot/test")
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	if fs.directory != expected {
		t.Fatalf("Expected %s Got %s", expected, fs.directory)
	}
}

func TestGetPublicKeyFile(t *testing.T) {
	dir := getKeyDirectory() + "test"
	expected := dir + "/pub.key"
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	pkFile := fs.GetPublicKeyFile()

	if expected != pkFile {
		t.Fatalf("Expected %s Got %s", expected, pkFile)
	}

	if err := dirCleanup(dir); err != nil {
		t.Fatal(err)
	}
}

func TestGetPrivateKeyFile(t *testing.T) {
	dir := getKeyDirectory() + "test"
	expected := dir + "/priv.key"
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	skFile := fs.GetPrivateKeyFile()

	if expected != skFile {
		t.Fatalf("Expected %s Got %s", expected, skFile)
	}

	if err := dirCleanup(dir); err != nil {
		t.Fatal(err)
	}
}

func TestGetAuthorizedKeyFile(t *testing.T) {
	dir := getKeyDirectory() + "test"
	expected := dir + "/authorized-keys"
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	skFile := fs.GetAuthorizedKeyFile()

	if expected != skFile {
		t.Fatalf("Expected %s Got %s", expected, skFile)
	}

	if err := dirCleanup(dir); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPublicKeyFile(t *testing.T) {
	clear := "Hello World"
	encoded := hex.EncodeToString([]byte(clear))
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(fs.GetPublicKeyFile(), []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}

	output, err := fs.LoadPublicKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != clear {
		t.Fatalf("Expected %s Got %s", clear, output)
	}
	if err := dirCleanup(fs.GetPublicKeyFile()); err != nil {
		t.Fatal(err)
	}
}

func TestLoadPrivateKeyFile(t *testing.T) {
	clear := "Hello World"
	encoded := hex.EncodeToString([]byte(clear))
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := ioutil.WriteFile(fs.GetPrivateKeyFile(), []byte(encoded), 0600); err != nil {
		t.Fatal(err)
	}

	output, err := fs.LoadPrivateKeyFile()
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != clear {
		t.Fatalf("Expected %s Got %s", clear, output)
	}
	if err := dirCleanup(fs.GetPrivateKeyFile()); err != nil {
		t.Fatal(err)
	}
}

func TestSaveKeyToFile(t *testing.T) {
	file := "testing.txt"
	input := "hello world"
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.SaveKeyToFile([]byte(input), file); err != nil {
		t.Fatal(err)
	}
	if err := dirCleanup(file); err != nil {
		t.Fatal(err)
	}
}

func TestExportedLoadFile(t *testing.T) {
	file := "testing.txt"
	input := "hello world"
	encoded := make([]byte, hex.EncodedLen(len([]byte(input))))
	hex.Encode(encoded, []byte(input))
	fs, err := New("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := fs.SaveKeyToFile(encoded, file); err != nil {
		t.Fatal(err)
	}
	output, err := LoadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if string(output) != input {
		t.Fatalf("Expected %s Got %s", input, output)
	}
	if err := dirCleanup(file); err != nil {
		t.Fatal(err)
	}
}
