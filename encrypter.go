package encrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

type Encrypter struct {
	key *[]byte
}

// NewEncrypter creates a new Encrypter instance with the provided key.
// The key should be a pointer to a byte slice that will be used for encryption.
//
// Parameters:
//
//	key - a pointer to a byte slice that represents the encryption key.
//
// Returns:
//
//	A pointer to an Encrypter instance initialized with the provided key.
//	- error: An error if the decryption process fails at any step.
func NewEncrypter(key *[]byte) *Encrypter {
	return &Encrypter{
		key: key,
	}
}

func (e *Encrypter) hash(iv, value string) []byte {
	mac := hmac.New(sha256.New, *e.key)
	mac.Write([]byte(iv + value))

	return mac.Sum(nil)
}

func (e *Encrypter) hashMatches(iv, value, expected string) (bool, error) {
	sig, err := hex.DecodeString(expected)

	if err != nil {
		return false, err
	}

	if !hmac.Equal(sig, e.hash(iv, value)) {
		return false, fmt.Errorf("the MAC is invalid")
	}

	return true, nil
}

// Decrypt decrypts the given base64 encoded string using the Encrypter's key.
// It first decodes the payload, checks the hash for integrity, and then
// decrypts the value using AES in CBC mode. The decrypted value is then
// unpadded and returned as a byte slice.
//
// Parameters:
//   - source: The base64 encoded string to be decrypted.
//
// Returns:
//   - []byte: The decrypted byte slice.
//   - error: An error if the decryption process fails at any step.
func (e *Encrypter) Decrypt(source string) ([]byte, error) {
	payload, err := e.decodePayload(source)
	if err != nil {
		return nil, err
	}

	// check if the hash matches the MAC
	if _, err := e.hashMatches(payload.Iv, payload.Value, payload.Mac); err != nil {
		return nil, err
	}

	// decode the iv
	iv, err := base64.StdEncoding.DecodeString(payload.Iv)
	if err != nil {
		return nil, err
	}

	// decode the value
	value, err := base64.StdEncoding.DecodeString(payload.Value)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(*e.key)
	if err != nil {
		return nil, err
	}

	if len(value) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	// CBC mode always works in whole blocks.
	if len(value)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(value, value)

	return e.unpadInput(value, block.BlockSize())
}

// Encrypt encrypts the given source byte slice using AES encryption in CBC mode.
// It first pads the input to ensure it is a multiple of the block size, then
// generates a new AES cipher block using the provided key. An initialization
// vector (IV) is created and filled with random data. The source data is then
// encrypted using the cipher block and IV. The resulting ciphertext and IV are
// encoded and returned as a string. If any error occurs during the process, it
// is returned.
//
// Parameters:
//   - source: The byte slice to be encrypted.
//
// Returns:
//   - A string containing the encoded IV and ciphertext.
//   - An error if any issue occurs during encryption.
func (e *Encrypter) Encrypt(source []byte) (string, error) {
	source = e.padInput(source)
	block, err := aes.NewCipher(*e.key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(source))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, source)

	return e.encodePayload(iv, ciphertext)
}

// Sha1 generates a SHA-1 HMAC for the given value using the Encrypter's key.
// It returns the resulting HMAC as a hexadecimal string.
//
// Parameters:
//
//	value - The input data to be hashed.
//
// Returns:
//
//	A hexadecimal string representation of the SHA-1 HMAC.
func (e *Encrypter) Sha1(value []byte) string {
	mac := hmac.New(sha1.New, *e.key)
	mac.Write(value)

	return hex.EncodeToString(mac.Sum(nil))
}
