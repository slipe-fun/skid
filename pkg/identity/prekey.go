package identity

import (
	"crypto/sha256"
	"errors"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/slipe-fun/skid/internal/crypto"
)

const PrekeyBundleDomainPrefix = "SKID-BUNDLE-V1"

type PublicPreKeyBundle struct {
	SPK_Pub       x448.Key
	OPK_Pub       x448.Key
	Kyber768_Pub  []byte
	Signature_Pub ed448.PublicKey
	Signature     []byte
}

type PrivatePreKeyBundle struct {
	SPK_Priv      x448.Key
	OPK_Priv      x448.Key
	Kyber768_Priv []byte
	Consumed      bool
}

func NewPreKeyBundle(publicDevice *PublicDevice, privateDevice *PrivateDevice) (*PublicPreKeyBundle, *PrivatePreKeyBundle, error) {
	kyberPublicKey, kyberSecretKey, err := crypto.GenerateKyberKeyPair()
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
		SPK_Pub:       SPK_Pub,
		OPK_Pub:       OPK_Pub,
		Kyber768_Pub:  kyberPublicKey,
		Signature_Pub: publicDevice.SignatureKey,
	}

	public.Signature = ed448.Sign(privateDevice.SignatureKey, BuildPrekeyBundleHash(public), PrekeyBundleDomainPrefix)

	private := &PrivatePreKeyBundle{
		SPK_Priv:      SPK_Priv,
		OPK_Priv:      OPK_Priv,
		Kyber768_Priv: kyberSecretKey,
	}

	return public, private, err
}

func GeneratePrekeyBundleMessage(prekey *PublicPreKeyBundle) []byte {
	out := make([]byte, 0, 16+len(prekey.OPK_Pub)+len(prekey.SPK_Pub)+len(prekey.Kyber768_Pub))

	out = append(out, []byte(PrekeyBundleDomainPrefix)...)
	out = append(out, prekey.SPK_Pub[:]...)
	out = append(out, prekey.OPK_Pub[:]...)
	out = append(out, prekey.Kyber768_Pub...)

	return out
}

func BuildPrekeyBundleHash(prekey *PublicPreKeyBundle) []byte {
	msg := GeneratePrekeyBundleMessage(prekey)
	sum := sha256.Sum256(msg)
	return sum[:]
}

func (prekey *PrivatePreKeyBundle) Consume() error {
	if prekey == nil {
		return errors.New("nil private prekey bundle")
	}
	if prekey.Consumed {
		return errors.New("prekey bundle already consumed")
	}

	prekey.Consumed = true
	clear(prekey.SPK_Priv[:])
	clear(prekey.OPK_Priv[:])
	clear(prekey.Kyber768_Priv)
	prekey.Kyber768_Priv = nil

	return nil
}
