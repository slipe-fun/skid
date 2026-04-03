package handshake

import (
	"errors"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func Initiate(
	aliceEK_Pub, aliceEK_Priv x448.Key,
	alicePublicDevice *identity.PublicDevice, alicePrivateDevice *identity.PrivateDevice,
	bobDevice *identity.PublicDevice, bobBundle *identity.PublicPreKeyBundle,
) ([]byte, *protocol.PreKeyMessage, error) {
	if valid := ed448.Verify(bobDevice.SignatureKey, identity.BuildPrekeyBundleHash(bobBundle), bobBundle.Signature, identity.PrekeyBundleDomainPrefix); !valid {
		return nil, nil, errors.New("invalid signature")
	}

	dh1, dh2, dh3, dh4, err := crypto.X3DH_Initiator(alicePrivateDevice.IK, aliceEK_Priv, bobDevice.IK, bobBundle.SPK_Pub, bobBundle.OPK_Pub)
	if err != nil {
		return nil, nil, err
	}

	kyberCiphertext, aliceKyberSecret, err := crypto.EncapsulateKyber(bobBundle.Kyber768_Pub)
	if err != nil {
		return nil, nil, err
	}

	aliceSharedKey := crypto.DeriveHybridKey(dh1[:], dh2[:], dh3[:], dh4[:], aliceKyberSecret)

	aliceInitialMessage := &protocol.PreKeyMessage{
		Version:         protocol.CurrentVersion,
		Type:            protocol.MessageTypePreKey,
		IKPub:           append([]byte(nil), alicePublicDevice.IK[:]...),
		EKPub:           append([]byte(nil), aliceEK_Pub[:]...),
		KyberCiphertext: kyberCiphertext,
	}

	return aliceSharedKey, aliceInitialMessage, nil
}
