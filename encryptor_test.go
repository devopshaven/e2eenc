package e2eenc_test

import (
	"bytes"
	"testing"

	"github.com/devopshaven/e2eenc"
	"github.com/stretchr/testify/assert"
)

func testEncryption(t *testing.T, enc e2eenc.Encryptor) {
	t.Helper()

	// Some random data to encrypt and decrypt
	dataToEncrypt := []byte("Hello, world!")

	// Check that the encryption struct is not nil
	if enc == nil {
		t.Fatalf("Encryption struct is nil")
	}

	t.Run("TestInvalidSize", func(t *testing.T) {
		if _, err := enc.Encrypt([]byte("")); err == nil {
			t.Errorf("Expected error, got nil")
			assert.ErrorIs(t, err, e2eenc.ErrShortData)
		}
	})

	// Encrypt the data
	cipherText, err := enc.Encrypt(dataToEncrypt)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt the ciphertext back into plaintext
	plainText, err := enc.Decrypt(cipherText)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Check that the original and final messages are the same
	if !bytes.Equal(dataToEncrypt, plainText) {
		t.Errorf("Decrypted data does not match original data")
	}
}

func TestAES(t *testing.T) {
	// Generate a new key
	key, err := e2eenc.GenerateAESKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	_, err = e2eenc.NewAESEncryptor([]byte("invalid"))
	assert.ErrorIs(t, err, e2eenc.ErrInvalidKeyLength)

	// Create an enc struct with the generated key
	enc, err := e2eenc.NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryption struct: %v", err)
	}

	// Check that the correct cipher is initialized.
	assert.Equal(t, enc.Type(), e2eenc.AESEncryptorType)

	// Run the encryption test
	testEncryption(t, enc)
}

func TestECDH(t *testing.T) {
	// Generate a new key
	enc, err := e2eenc.NewECDHEncrypter()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	assert.Equal(t, enc.Type(), e2eenc.ECDHEncryptorType)

	// Run the encryption test
	testEncryption(t, enc)
}
