package crypto

//Cryptor interface for encrypting and decrypting
type Cryptor interface {
	Encrypt()
	Decrypt()
}

//KeysGenerator for asymmetric encryption
type KeysGenerator interface {
	CreateKeys() error
}

//KeyGenerator for symmetric encryption
type KeyGenerator interface {
	CreateKey() error
}
