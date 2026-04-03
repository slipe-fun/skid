package identity

import (
	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/slipe-fun/skid/internal/crypto"
)

type PublicDevice struct {
	IK           x448.Key
	SignatureKey ed448.PublicKey
}

type PrivateDevice struct {
	IK           x448.Key
	SignatureKey ed448.PrivateKey
}

func NewDevice() (*PublicDevice, *PrivateDevice, error) {
	signature_pub, signature_priv, err := crypto.GenerateEd448KeyPair()
	if err != nil {
		return &PublicDevice{}, &PrivateDevice{}, err
	}

	IK_Pub, IK_Priv, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, nil, err
	}

	public := PublicDevice{
		IK:           IK_Pub,
		SignatureKey: signature_pub,
	}

	private := PrivateDevice{
		IK:           IK_Priv,
		SignatureKey: signature_priv,
	}

	return &public, &private, nil
}
