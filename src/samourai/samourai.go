package samourai

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// DecryptAES256CBC decrypts the given ciphertext using AES-256-CBC
func DecryptAES256CBC(ciphertextBase64 string, password string, iterations int) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return "", err
	}

	// Extract salt
	if len(ciphertext) < 16 {
		return "", fmt.Errorf("ciphertext too short to extract salt")
	}

	salt := ciphertext[8:16]

	// Derive the key using PBKDF2
	key := pbkdf2.Key([]byte(password), salt, iterations, 32, sha256.New)

	// Create a new AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// Use first block as IV
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

// ReadPayload reads the JSON file and extracts the 'payload' value
func ReadPayload(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return "", err
	}

	var data map[string]interface{}
	if err := unmarshal(bytes, &data); err != nil {
		return "", err
	}

	payload, exists := data["payload"].(string)
	if !exists {
		return "", fmt.Errorf("'payload' key not found or is not a string in JSON")
	}

	return payload, nil
}

func unmarshal(bytes []byte, data *map[string]interface{}) error {
	if err := json.Unmarshal(bytes, &data); err != nil {
		// garbled json file
		bytesStr := string(bytes)
		closingBracket := strings.IndexRune(bytesStr, '}')
		actualJson := bytesStr[0 : closingBracket+1]

		if err := json.Unmarshal([]byte(actualJson), &data); err != nil {
			return err
		}
	}

	return nil
}
