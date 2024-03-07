package e2eenc_test

import (
	"bytes"
	"testing"

	"github.com/devopshaven/e2eenc"
)

func testEncryption(e e2eenc.Encryptor, t *testing.T) {
	t.Helper()

	// Some random data to encrypt and decrypt
	dataToEncrypt := []byte("Hello, world!")

	// Encrypt the data
	cipherText, err := e.Encrypt(dataToEncrypt)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Decrypt the ciphertext back into plaintext
	plainText, err := e.Decrypt(cipherText)
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

	// Create an e struct with the generated key
	e, err := e2eenc.NewAESEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryption struct: %v", err)
	}

	// Run the encryption test
	testEncryption(e, t)
}

func TestECDH(t *testing.T) {
	// Generate a new key
	e, err := e2eenc.NewECDHEncrypter()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Run the encryption test
	testEncryption(e, t)

}
