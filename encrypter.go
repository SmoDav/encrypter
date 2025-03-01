package encrypter

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
)

type Encrypter struct {
	key *[]byte
}

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
