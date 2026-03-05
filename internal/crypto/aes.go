package crypto

import (
	"crypto/sha256"
	"errors"
	"io"

	"github.com/tink-crypto/tink-go/v2/aead/subtle"
	"golang.org/x/crypto/hkdf"
)

func NewAes(key []byte) (*subtle.AESGCMSIV, error) {
	return subtle.NewAESGCMSIV(key)
}

func DeriveAesKey(sessionKey, salt []byte) ([]byte, error) {
	kdf := hkdf.New(sha256.New, sessionKey, salt, []byte("aes-key-derivation"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, err
	}
	return key, nil
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
