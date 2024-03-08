package e2eenc

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AESEncryptor encrypts and decrypts data using AES in CBC mode.
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
// You can initialize this encryptor with NewAESEncryptor(key) and use it with Encrypt and Decrypt.
type AESEncryptor struct {
	key []byte
}

// GenerateAESKey generates a random 256-bit key and returns it.
func GenerateAESKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %v", err)
	}

	return key, nil
}

// NewAESEncryptor creates a new encryption struct with the provided key.
func NewAESEncryptor(key []byte) (*AESEncryptor, error) {
	if len(key) != 32 { // 256 bits
		return nil, fmt.Errorf("%w: %d", ErrInvalidKeyLength, len(key))
	}

	return &AESEncryptor{key: key}, nil
}

// Encrypt encrypts the provided data with AES in CBC mode and returns the encrypted data and any error that occurred.
func (e *AESEncryptor) Encrypt(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, ErrShortData
	}

	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	// Padding
	padding := aes.BlockSize - len(data)%aes.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	data = append(data, padtext...)

	// The IV needs to be unique, but not secure. Therefore it's common to include it at the beginning of the ciphertext.
	cipherText := make([]byte, aes.BlockSize+len(data))
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to read random data: %v", err)
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], data)

	return cipherText, nil
}

// Decrypt decrypts the provided ciphertext with AES in CBC mode and returns the decrypted data and any error that occurred.
func (e *AESEncryptor) Decrypt(cipherText []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	if len(cipherText) < aes.BlockSize {
		return nil, ErrShortData
	}

	// The IV needs to be unique, but not secure. Therefore it's common to include it at the beginning of the ciphertext.
	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)
	// Unpadding
	padding := cipherText[len(cipherText)-1]
	cipherText = cipherText[:len(cipherText)-int(padding)]

	return cipherText, nil
}

// Type returns the type of the encryptor.
func (e *AESEncryptor) Type() EncryptorType {
	return AESEncryptorType
}
