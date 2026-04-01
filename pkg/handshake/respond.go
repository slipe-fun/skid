package handshake

import (
	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func Respond(
	bobBundle *identity.PrivatePreKeyBundle,
	aliceMsg *protocol.InitialMessage,
) ([]byte, error) {
	b_dh1, b_dh2, b_dh3, b_dh4 := crypto.X3DH_Responder(bobBundle.IK_Priv, bobBundle.SPK_Priv, bobBundle.OPK_Priv, aliceMsg.IK_Pub, aliceMsg.EK_Pub)

	bobKyberSecret, err := crypto.DecapsulateKyber(bobBundle.Kyber768_Priv, aliceMsg.KyberCiphertext)
	if err != nil {
		panic(err)
	}

	bobSharedKey := crypto.DeriveHybridKey(b_dh1[:], b_dh2[:], b_dh3[:], b_dh4[:], bobKyberSecret)

	return bobSharedKey, err
}
