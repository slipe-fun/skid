package handshake

import (
	"fmt"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/cloudflare/circl/sign/ed448"
	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func Respond(
	bobDevice *identity.PrivateDevice, bobBundle *identity.PrivatePreKeyBundle,
	aliceDevice *identity.PublicDevice, aliceMsg *protocol.PreKeyMessage,
) ([]byte, error) {
	if aliceMsg == nil {
		return nil, fmt.Errorf("nil prekey message")
	}
	if aliceMsg.Version != protocol.CurrentVersion {
		return nil, fmt.Errorf("unsupported prekey message version: %d", aliceMsg.Version)
	}
	if aliceMsg.Type != protocol.MessageTypePreKey {
		return nil, fmt.Errorf("unexpected prekey message type: %d", aliceMsg.Type)
	}
	if aliceMsg.Message == nil {
		return nil, fmt.Errorf("ratchet message is required")
	}

	if valid := ed448.Verify(aliceDevice.SignatureKey, protocol.BuildPrekeyMessageBundleHash(aliceMsg), aliceMsg.Signature, protocol.PrekeyMessageBundleDomainPrefix); !valid {
		return nil, fmt.Errorf("invalid signature")
	}

	aliceIK, err := decodeX448Key(aliceMsg.IKPub)
	if err != nil {
		return nil, err
	}

	aliceEK, err := decodeX448Key(aliceMsg.EKPub)
	if err != nil {
		return nil, err
	}

	b_dh1, b_dh2, b_dh3, b_dh4, err := crypto.X3DH_Responder(bobDevice.IK, bobBundle.SPK_Priv, bobBundle.OPK_Priv, aliceIK, aliceEK)
	if err != nil {
		return nil, err
	}

	bobKyberSecret, err := crypto.DecapsulateKyber(bobBundle.Kyber768_Priv, aliceMsg.KyberCiphertext)
	if err != nil {
		return nil, err
	}

	bobSharedKey := crypto.DeriveHybridKey(b_dh1[:], b_dh2[:], b_dh3[:], b_dh4[:], bobKyberSecret)

	return bobSharedKey, err
}

func decodeX448Key(raw []byte) (x448.Key, error) {
	var key x448.Key
	if len(raw) != len(key) {
		return x448.Key{}, fmt.Errorf("invalid x448 key length: got %d want %d", len(raw), len(key))
	}
	copy(key[:], raw)
	return key, nil
}
