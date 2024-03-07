# e2eenc

<!-- [![Build Status](https://travis-ci.com/<username>/<repo>.svg?branch=master)](https://travis-ci.com/<username>/<repo>) -->

[![Coverage Status](https://coveralls.io/repos/github/devopshaven/e2eenc/badge.svg?branch=main)](https://coveralls.io/repos/github/devopshaven/e2eenc?branch=main)

`e2eenc` is a simple and effective library for end-to-end encryption in Go. It provides implementations of AES and ECDH encryption algorithms.

## Features

- AES encryption in CBC mode.
- ECDH encryption.
- 256-bit key generation for AES.
- Easy to use interface for encryption and decryption.

## Installation

Use go get to install this package:

```bash
go get github.com/devopshaven/e2eenc
```

## Usage

Here is an example of how to use this package:

```go
package main

import (
	"fmt"
	"github.com/devopshaven/e2eenc"
)

func main() {
	// Generate a new key
	key, err := e2eenc.GenerateAESKey()
	if err != nil {
		fmt.Println("Failed to generate key:", err)
	}

	// Create an e struct with the generated key
	e, err := e2eenc.NewAESEncryptor(key)
	if err != nil {
		fmt.Println("Failed to create encryption struct:", err)
	}

	// Some random data to encrypt and decrypt
	dataToEncrypt := []byte("Hello, world!")

	// Encrypt the data
	cipherText, err := e.Encrypt(dataToEncrypt)
	if err != nil {
		fmt.Println("Failed to encrypt data:", err)
	}

	// Decrypt the ciphertext back into plaintext
	plainText, err := e.Decrypt(cipherText)
	if err != nil {
		fmt.Println("Failed to decrypt data:", err)
	}

	// Print the original and decrypted messages
	fmt.Println("Original message:", string(dataToEncrypt))
	fmt.Println("Decrypted message:", string(plainText))
}
```

## Testing

You can run the tests with the following command:

```bash
go test ./...
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Made with ❤️ by neverkn0wn