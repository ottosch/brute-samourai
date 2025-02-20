package bip38

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

const iterations = 15000

// DecryptWithPassphrase decrypts the single-line ciphertext in base64 using the passphrase
// returns the decrypted string (which might not be the correct one) or an error
func DecryptWithPassphrase(ciphertextBase64 string, passphrase string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}

	// Extract the salt from bytes 8 to 15
	if len(ciphertext) < 16 {
		return "", fmt.Errorf("ciphertext too short to extract salt")
	}
	salt := ciphertext[8:16]

	// Derive the key using PBKDF2
	key := pbkdf2.Key([]byte(passphrase), salt, iterations, 32, sha256.New)

	// Create a new AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// The IV is typically the first block of the ciphertext
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	// Decrypt the ciphertext
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// Remove padding (PKCS#7)
	padding := int(ciphertext[len(ciphertext)-1])
	ciphertext = ciphertext[:len(ciphertext)-padding]

	return string(ciphertext), nil
}
