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
	aliceIK_Pub, aliceIK_Priv x448.Key,
	aliceEK_Pub, aliceEK_Priv x448.Key,
	bobBundle *identity.PublicPreKeyBundle,
) ([]byte, *protocol.InitialMessage, error) {
	if valid := ed448.Verify(bobBundle.Signature_Pub, identity.BuildPrekeyBundleHash(bobBundle), bobBundle.Signature, identity.PrekeyBundleDomainPrefix); !valid {
		return nil, nil, errors.New("invalid signature")
	}

	dh1, dh2, dh3, dh4, err := crypto.X3DH_Initiator(aliceIK_Priv, aliceEK_Priv, bobBundle.IK_Pub, bobBundle.SPK_Pub, bobBundle.OPK_Pub)
	if err != nil {
		return nil, nil, err
	}

	kyberCiphertext, aliceKyberSecret, err := crypto.EncapsulateKyber(bobBundle.Kyber768_Pub)
	if err != nil {
		return nil, nil, err
	}

	aliceSharedKey := crypto.DeriveHybridKey(dh1[:], dh2[:], dh3[:], dh4[:], aliceKyberSecret)

	aliceInitialMessage := &protocol.InitialMessage{
		IK_Pub:          aliceIK_Pub,
		EK_Pub:          aliceEK_Pub,
		KyberCiphertext: kyberCiphertext,
	}

	return aliceSharedKey, aliceInitialMessage, err
}
