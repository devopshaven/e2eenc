// Package e2eenc provides functionality for end-to-end encryption using different encryption methods such as AES and ECDH.
//
// The package provides an interface 'Encryptor' which is implemented by different types of encryptors.
// Each encryptor must provide methods to Encrypt and Decrypt data, and return its Type.
//
// Currently, the package supports the following types of encryptors:
//
//   - AES Encryptor: This encryptor uses AES (Advanced Encryption Standard) for encryption and decryption.
//     It requires a 256-bit key which can be generated using the GenerateAESKey function.
//     An instance of the AES Encryptor can be created using the NewAESEncryptor function.
//
//   - ECDH Encryptor: This encryptor uses ECDH (Elliptic Curve Diffie-Hellman) for encryption and decryption.
//     It can be configured with a public and/or private key using the WithPublicKey and WithPrivateKey options respectively.
//     If no private key is provided, a new one will be generated.
//     An instance of the ECDH Encryptor can be created using the NewECDHEncryptor function.
//
// The package also provides test functions to test the encryption and decryption functionality of each encryptor.
package e2eenc
