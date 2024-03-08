package e2eenc

import "errors"

type EncryptorType string

const (
	ECDHEncryptorType EncryptorType = "ECDH"
	AESEncryptorType  EncryptorType = "AES"
)

var (
	// ErrShortData is returned when the provided text is too short to be encrypted.
	ErrShortData        = errors.New("data is too short")
	ErrInvalidKeyLength = errors.New("invalid key length")
)

type Encryptor interface {
	// Encrypt encrypts the provided data.
	Encrypt([]byte) ([]byte, error)

	// Decrypt decrypts the provided data.
	Decrypt([]byte) ([]byte, error)

	// Type returns the type of the encryptor.
	Type() EncryptorType
}
