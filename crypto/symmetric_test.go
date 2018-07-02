package crypto_test

import (
	"bytes"
	"testing"

	"github.com/jamesbcook/chatbot-external-api/crypto"
)

func TestSymmetricCreateKey(t *testing.T) {
	sym := &crypto.Symmetric{}
	if err := sym.CreateKey(nil); err != nil {
		t.Fatal(err)
	}
	sym2 := &crypto.Symmetric{}
	nonce := [12]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	if err := sym2.CreateKey(&nonce); err != nil {
		t.Fatal(err)
	}
}

func TestSymmetricEncrypt(t *testing.T) {
	input := []byte("Hello World")
	sym := &crypto.Symmetric{}
	if err := sym.CreateKey(nil); err != nil {
		t.Fatal(err)
	}
	output, err := sym.Encrypt(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(output) <= 0 {
		t.Fatal("Output zero in size")
	}
}
func TestSymmetricDecrypt(t *testing.T) {
	input := []byte("Hello World")
	sym := &crypto.Symmetric{}
	if err := sym.CreateKey(nil); err != nil {
		t.Fatal(err)
	}
	output, err := sym.Encrypt(input)
	if err != nil {
		t.Fatal(err)
	}
	cleartext, err := sym.Decrypt(output)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Compare(input, cleartext) != 0 {
		t.Fatalf("Expected %s Got %s", input, cleartext)
	}
	sym.Nonce[3] = 0x01
	_, err = sym.Decrypt(output)
	if err == nil {
		t.Fatal("This should have failed")
	}
}
