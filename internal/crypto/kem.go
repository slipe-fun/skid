package crypto

import (
	"crypto/rand"
	"errors"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

func GenerateKyberKeyPair() ([]byte, []byte, error) {
	pk, sk, err := kyber768.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	pkBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return pkBytes, skBytes, nil
}

func EncapsulateKyber(pkBytes []byte) ([]byte, []byte, error) {
	if len(pkBytes) != kyber768.PublicKeySize {
		return nil, nil, errors.New("invalid public key size")
	}

	pk := new(kyber768.PublicKey)
	pk.Unpack(pkBytes)

	return kyber768.Scheme().Encapsulate(pk)
}

func DecapsulateKyber(skBytes, ct []byte) ([]byte, error) {
	if len(skBytes) != kyber768.PrivateKeySize {
		return nil, errors.New("invalid secret key size")
	}

	if len(ct) != kyber768.CiphertextSize {
		return nil, errors.New("invalid ciphertext size")
	}

	sk := new(kyber768.PrivateKey)
	sk.Unpack(skBytes)

	return kyber768.Scheme().Decapsulate(sk, ct)
}
