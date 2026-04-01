package crypto

import (
	"errors"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
)

func NewAes(key []byte) (*subtle.AESGCMSIV, error) {
	return subtle.NewAESGCMSIV(key)
}

func Encrypt(key, plaintext, aad []byte) ([]byte, []byte, error) {
	aes, err := NewAes(key)
	if err != nil {
		return nil, nil, err
	}

	fullResult, err := aes.Encrypt(plaintext, aad)
	if err != nil {
		return nil, nil, err
	}

	if len(fullResult) < 12 {
		return nil, nil, errors.New("failed to encrypt")
	}

	return fullResult[12:], fullResult[:12], nil
}

func Decrypt(key, ciphertext, iv, aad []byte) ([]byte, error) {
	if len(iv) != 12 {
		return nil, errors.New("invalid IV length: must be exactly 12 bytes")
	}

	aes, err := NewAes(key)
	if err != nil {
		return nil, err
	}

	fullCiphertext := make([]byte, 0, len(iv)+len(ciphertext))
	fullCiphertext = append(fullCiphertext, iv...)
	fullCiphertext = append(fullCiphertext, ciphertext...)

	return aes.Decrypt(fullCiphertext, aad)
}
