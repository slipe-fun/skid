package identity

import (
	"github.com/cloudflare/circl/dh/x448"
	"github.com/slipe-fun/skid/internal/crypto"
)

type PublicPreKeyBundle struct {
	IK_Pub       x448.Key
	SPK_Pub      x448.Key
	OPK_Pub      x448.Key
	Kyber768_Pub []byte
}

type PrivatePreKeyBundle struct {
	IK_Priv       x448.Key
	SPK_Priv      x448.Key
	OPK_Priv      x448.Key
	Kyber768_Priv []byte
}

func NewPreKeyBundle() (*PublicPreKeyBundle, *PrivatePreKeyBundle, error) {
	kyberPublicKey, kyberSecretKey, err := crypto.GenerateKyberKeyPair()
	if err != nil {
		return nil, nil, err
	}

	IK_Pub, IK_Priv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	SPK_Pub, SPK_Priv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	OPK_Pub, OPK_Priv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	public := &PublicPreKeyBundle{
		IK_Pub:       IK_Pub,
		SPK_Pub:      SPK_Pub,
		OPK_Pub:      OPK_Pub,
		Kyber768_Pub: kyberPublicKey,
	}

	private := &PrivatePreKeyBundle{
		IK_Priv:       IK_Priv,
		SPK_Priv:      SPK_Priv,
		OPK_Priv:      OPK_Priv,
		Kyber768_Priv: kyberSecretKey,
	}

	return public, private, err
}
