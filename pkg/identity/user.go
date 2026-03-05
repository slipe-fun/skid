package identity

import (
	"github.com/slipe-fun/skid/internal/crypto"
)

type UserPrivate struct {
	KyberKey   []byte
	ECDHKey    []byte
	Ed25519Key []byte
}

type UserPublic struct {
	KyberKey   []byte `json:"kyber_key"`
	ECDHKey    []byte `json:"ecdh_key"`
	Ed25519Key []byte `json:"ed_key"`
}

func NewUser() (*UserPrivate, *UserPublic, error) {
	kyberPublicKey, kyberSecretKey, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return nil, nil, err
	}

	ecdhPublicKey, ecdhSecretKey, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	ed25519PublicKey, ed25519SecretKey, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	public := &UserPublic{
		KyberKey:   kyberPublicKey,
		ECDHKey:    ecdhPublicKey,
		Ed25519Key: ed25519PublicKey,
	}

	private := &UserPrivate{
		KyberKey:   kyberSecretKey,
		ECDHKey:    ecdhSecretKey,
		Ed25519Key: ed25519SecretKey,
	}

	return private, public, nil
}
