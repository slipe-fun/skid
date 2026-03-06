package identity

import (
	"github.com/slipe-fun/skid/internal/crypto"
)

type UserPrivate struct {
	KyberKey []byte
	ECDHKey  []byte
}

type UserPublic struct {
	KyberKey []byte `json:"kyber_key"`
	ECDHKey  []byte `json:"ecdh_key"`
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

	public := &UserPublic{
		KyberKey: kyberPublicKey,
		ECDHKey:  ecdhPublicKey,
	}

	private := &UserPrivate{
		KyberKey: kyberSecretKey,
		ECDHKey:  ecdhSecretKey,
	}

	return private, public, nil
}
