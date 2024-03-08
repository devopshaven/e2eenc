package e2eenc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"fmt"
	"io"
)

type ECDHEncrypter struct {
	privateKey *ecdh.PrivateKey
	publicKey  *ecdh.PublicKey
}

type ECDHEncrypterOption func(*ECDHEncrypter)

// WithPrivateKey sets the private key for the ECDHEncrypter.
func WithPrivateKey(privKey *ecdh.PrivateKey) ECDHEncrypterOption {
	return func(e *ECDHEncrypter) {
		e.privateKey = privKey
	}
}

// WithPublicKey sets the public key for the ECDHEncrypter.
func WithPublicKey(pubKey *ecdh.PublicKey) ECDHEncrypterOption {
	return func(e *ECDHEncrypter) {
		e.publicKey = pubKey
	}
}

func NewECDHEncrypter(opts ...ECDHEncrypterOption) (*ECDHEncrypter, error) {
	enc := new(ECDHEncrypter)

	// Apply options
	for _, opt := range opts {
		opt(enc)
	}

	if enc.privateKey == nil {
		privKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("failed to generate key: %v", err)
		}

		enc.privateKey = privKey
	}

	return enc, nil
}

// Encrypt encrypts the provided data with AES in CFB mode and returns
// the encrypted data and any error that occurred.
func (e *ECDHEncrypter) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrShortData
	}

	block, err := aes.NewCipher(e.privateKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))

	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to read random data: %v", err)
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], data)

	return ciphertext, nil
}

func (e *ECDHEncrypter) Decrypt(data []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.privateKey.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(data) < aes.BlockSize {
		return nil, ErrShortData
	}

	iv := data[:aes.BlockSize]
	data = data[aes.BlockSize:]

	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(data, data)

	return data, nil
}

// Type returns the type of the encryptor.
func (e *ECDHEncrypter) Type() EncryptorType {
	return ECDHEncryptorType
}
