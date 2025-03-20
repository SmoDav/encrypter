package encrypter

import (
	"crypto/aes"
	"crypto/hmac"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
)

func keyForTesting() string {
	return "base64:VpGALUhHPT9U76jE/VEodvVAdniEsyyaZaBPBssONqI="
}

func TestEncryption(t *testing.T) {
	_, err := ParseKey("base64:-")
	if err == nil {
		t.Errorf("expected an error, but got nil")
	}

	_, err = ParseKey("1234567890asdfgh")
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}

	key, err := ParseKey(keyForTesting())
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}

	e := NewEncrypter(key)

	t.Run("decodes base64 encoded payloads", func(t *testing.T) {
		t.Parallel()

		_, err := e.decodePayload(base64.StdEncoding.EncodeToString([]byte{}))
		if err == nil {
			t.Errorf("expected an error, but got nil")
		}

		_, err = e.decodePayload(base64.StdEncoding.EncodeToString([]byte("{invalid json:}")))
		if err == nil {
			t.Errorf("expected an error, but got nil")
		}

		dec, err := e.decodePayload(base64.StdEncoding.EncodeToString([]byte(`{"iv":"iv","value":"value","mac":"mac"}`)))
		if err != nil {
			t.Errorf("expected an error, but got nil")
		}

		if dec.Iv != "iv" || dec.Value != "value" || dec.Mac != "mac" {
			t.Errorf("expected valid payload, but got %v", dec)
		}
	})

	t.Run("generates valid hashes", func(t *testing.T) {
		t.Parallel()
		mac := e.hash("iv", "value")
		if len(mac) == 0 {
			t.Errorf("expected a valid MAC, but got an empty string")
		}

		encodedHash := hex.EncodeToString(mac)

		matches, err := e.hashMatches("iv", "value", "fake")

		if err == nil {
			t.Errorf("expected an error, but got nil")
		}

		if matches {
			t.Error("expected hash not to match, but it did.")
		}

		matches, err = e.hashMatches("iv", "value", encodedHash)

		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}

		if !matches {
			t.Error("expected MAC to match but failed.")
		}

		mac = e.hash("iv", "diff value")
		encodedHash = hex.EncodeToString(mac)
		matches, err = e.hashMatches("iv", "value", encodedHash)

		if err == nil {
			t.Errorf("expected an error, but got nil")
		}
		if matches {
			t.Error("expected hash not to match, but it did.")
		}
	})

	t.Run("decodes and encodes payloads", func(t *testing.T) {
		t.Parallel()

		enc, err := e.Encrypt([]byte("testing"))
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}

		if enc == "" {
			t.Error("expected a valid encoded string, but got an empty string")
		}

		if !strings.HasPrefix(enc, "eyJ") {
			t.Errorf("expected valid base64 encoded string, but got %s", enc)
		}

		dec, err := e.Decrypt(enc)
		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}

		if string(dec) != "testing" {
			t.Errorf("expected decrypted value to be 'testing', but got %s", dec)
		}

		dec, err = e.Decrypt("fake string")
		if err == nil {
			t.Errorf("expected an error, but got nil")
		}

		if dec != nil {
			t.Errorf("expected nil value, but got %s", string(dec))
		}
	})

	t.Run("pads and unpads values", func(t *testing.T) {
		padded := e.padInput([]byte("testing"))
		if len(padded) != aes.BlockSize {
			t.Errorf("expected a padded value, but got %d", len(padded))
		}

		if _, err := e.unpadInput(padded, 0); err == nil {
			t.Error("expected an error, but got nil")
		}

		if _, err = e.unpadInput(padded, aes.BlockSize+1); err == nil {
			t.Error("expected an error, but got nil")
		}

		padded = e.padInput([]byte("testing111111115"))

		un, err := e.unpadInput(padded, aes.BlockSize)

		if err != nil {
			t.Errorf("expected no error, but got %v", err)
		}

		if string(un) != "testing111111115" {
			t.Errorf("expected original string but got %s", string(un))
		}
	})

	t.Run("generates a valid sha1 hash", func(t *testing.T) {
		val := e.Sha1([]byte("testing"))

		if !hmac.Equal([]byte(val), []byte("67696b8f5f6211edbec4ae7110f4a365e9ea976f")) {
			t.Errorf("expected valid sha1 hash, but got %s", val)
		}
	})
}
