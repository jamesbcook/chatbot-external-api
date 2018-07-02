package network

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func setTestKeys(t *testing.T) {
	priv, err := hex.DecodeString("4a432aff63c807241f107d8615e8bf051e03e9492be22a1321d046c5bba2cdcc7bb61e895ada9a1310598d6ebfee61a04c8e3995add57e0babc1e2c6e37aa417")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString("7bb61e895ada9a1310598d6ebfee61a04c8e3995add57e0babc1e2c6e37aa417")
	if err != nil {
		t.Fatal(err)
	}
	if err := SetSecretKeyPair(priv, pub); err != nil {
		t.Fatal(err)
	}
}

func TestInternalSignMessage(t *testing.T) {
	expected := "092c91581813253a878640dd9fdcbed7cc8605f5543bfc9062c3636b33e13f36962bec9296e21b65d44438481185dcf196b7a7e4be812d198bc0781e920d1f0b"
	message := []byte("Hello World")
	setTestKeys(t)
	output := signMessage(hashMessage(message))
	if len(output) <= 0 {
		t.Fatal("Output should not be zero")
	}
	if expected != hex.EncodeToString(output) {
		t.Fatalf("Expected %s\nGot %x\n", expected, output)
	}
}

func TestInternalVerifyMessage(t *testing.T) {
	input := []byte("Hello World")
	signedMessage := signMessage(hashMessage(input))
	var message []byte
	message = append(message, signedMessage...)
	message = append(message, input...)
	pubkey, err := hex.DecodeString(GetIdentityKey())
	if err != nil {
		t.Fatal(err)
	}
	if !verifyMessage(pubkey, message) {
		t.Fatal("Message signature did not match")
	}
}

func TestAddAuthKey(t *testing.T) {
	key := GetIdentityKey()
	AddAuthKey([]byte(key))
}

func TestGetAuthKeys(t *testing.T) {
	found := false
	key := GetIdentityKey()
	decodeKey, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	AddAuthKey(decodeKey)
	keys := GetAuthKeys()
	for x := range keys {
		if bytes.Compare(keys[x], decodeKey) == 0 {
			found = true
		}
	}
	if !found {
		t.Fatal("Didn't find key")
	}
}

func TestAuthorizedKey(t *testing.T) {
	key := GetIdentityKey()
	decodeKey, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	AddAuthKey(decodeKey)
	if !AuthorizedKey(decodeKey) {
		t.Fatal("This should have matched")
	}
	if AuthorizedKey([]byte("Something random")) {
		t.Fatal("This should have not matched")
	}
}
