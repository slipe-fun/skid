package crypto

import (
	"crypto/rand"

	"github.com/cloudflare/circl/sign/ed448"
)

func GenerateEd448KeyPair() ([]byte, []byte, error) {
	pk, sk, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return ed448.PublicKey{}, ed448.PrivateKey{}, err
	}

	return pk, sk, nil
}
