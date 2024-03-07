package e2eenc

type EncryptorType string

const (
	ECDHEncryptorType EncryptorType = "ECDH"
)

type Encryptor interface {
	// Encrypt encrypts the provided data.
	Encrypt([]byte) ([]byte, error)

	// Decrypt decrypts the provided data.
	Decrypt([]byte) ([]byte, error)

	// Type returns the type of the encryptor.
	Type() EncryptorType
}
