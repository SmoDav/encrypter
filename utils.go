package encrypter

import (
	"bytes"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type EncryptedPayload struct {
	Iv    string `json:"iv"`
	Value string `json:"value"`
	Mac   string `json:"mac"`
}

func ParseKey(key string) (*[]byte, error) {
	if after, found := strings.CutPrefix(key, "base64:"); found {
		decoded, err := base64.StdEncoding.DecodeString(after)
		if err != nil {
			return nil, err
		}

		return &decoded, nil
	}

	parsed := []byte(key)

	return &parsed, nil
}

func (e *Encrypter) decodePayload(source string) (*EncryptedPayload, error) {
	out, err := base64.StdEncoding.DecodeString(source)

	if err != nil {
		return nil, err
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("invalid source string: %s", source)
	}

	var parsed EncryptedPayload

	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}

	return &parsed, nil
}

func (e *Encrypter) encodePayload(iv, value []byte) (string, error) {
	parsed := &EncryptedPayload{
		Iv:    base64.StdEncoding.EncodeToString(iv),
		Value: base64.StdEncoding.EncodeToString(value),
		Mac:   "",
	}

	parsed.Mac = hex.EncodeToString(e.hash(parsed.Iv, parsed.Value))

	out, err := json.Marshal(&parsed)

	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(out), nil
}

func (e *Encrypter) padInput(source []byte) []byte {
	var sourceBlock []byte
	length := len(source)

	if length%aes.BlockSize != 0 {
		extendBlock := aes.BlockSize - (length % aes.BlockSize)
		sourceBlock = make([]byte, length+extendBlock)
		copy(sourceBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	} else {
		sourceBlock = make([]byte, length)
	}
	copy(sourceBlock, source)

	return sourceBlock
}

func (e *Encrypter) unpadInput(source []byte, blockLen int) ([]byte, error) {
	if blockLen <= 0 {
		return nil, fmt.Errorf("invalid blockLen %d", blockLen)
	}

	if len(source)%blockLen != 0 || len(source) == 0 {
		return nil, fmt.Errorf("invalid data len %d", len(source))
	}

	// get the length that we have padded the string
	padlen := int(source[len(source)-1])

	// check if the string is padded
	if padlen > blockLen || padlen == 0 {
		return source, nil
	}

	// check padding
	pad := source[len(source)-padlen:]
	for i := 0; i < padlen; i++ {
		if pad[i] != byte(padlen) {
			return nil, fmt.Errorf("invalid padding")
		}
	}

	return source[:len(source)-padlen], nil
}
