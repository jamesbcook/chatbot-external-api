package crypto

//Cryptor interfafce for encrypting and decrypting
type Cryptor interface {
	Encrypt()
	Decrypt()
}

//KeysGenerator for asymmectric ecnryption
type KeysGenerator interface {
	CreateKeys() error
}

//KeyGenerator for symmectric ecnryption
type KeyGenerator interface {
	CreateKey() error
}
