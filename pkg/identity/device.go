package identity

import (
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/slipe-fun/skid/internal/crypto"
)

type PublicDevice struct {
	SignatureKey ed448.PublicKey
}

type PrivateDevice struct {
	SignatureKey ed448.PrivateKey
}

func NewDevice() (*PublicDevice, *PrivateDevice, error) {
	signature_pub, signature_priv, err := crypto.GenerateEd448KeyPair()
	if err != nil {
		return &PublicDevice{}, &PrivateDevice{}, err
	}

	public := PublicDevice{
		SignatureKey: signature_pub,
	}

	private := PrivateDevice{
		SignatureKey: signature_priv,
	}

	return &public, &private, nil
}
