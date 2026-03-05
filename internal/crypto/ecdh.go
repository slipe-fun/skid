package crypto

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/dh/x448"
)

func GenerateECDHKeyPair() ([]byte, []byte, error) {
	var pk, sk x448.Key

	if _, err := io.ReadFull(rand.Reader, sk[:]); err != nil {
		return nil, nil, errors.New("crypto/rand is unavailable: " + err.Error())
	}
	x448.KeyGen(&pk, &sk)

	return pk[:], sk[:], nil
}

func DeriveECDHSharedSecret(sk, pk []byte) ([]byte, error) {
	if len(sk) != 56 || len(pk) != 56 {
		return nil, errors.New("invalid ECDH key length: must be exactly 56 bytes")
	}

	var shared, secret, public x448.Key
	copy(secret[:], sk)
	copy(public[:], pk)

	if ok := x448.Shared(&shared, &secret, &public); !ok {
		return nil, errors.New("invalid public key")
	}

	return shared[:], nil
}
