package handshake

import (
	"fmt"

	"github.com/cloudflare/circl/dh/x448"
	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
	"github.com/slipe-fun/skid/pkg/protocol"
)

func Respond(
	bobDevice *identity.PrivateDevice, bobBundle *identity.PrivatePreKeyBundle,
	_ *identity.PublicDevice, aliceMsg *protocol.PreKeyMessage,
) ([]byte, error) {
	if bobBundle == nil {
		return nil, fmt.Errorf("nil prekey bundle")
	}
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
	if bobBundle.Consumed {
		return nil, fmt.Errorf("prekey bundle already consumed")
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
	if err := bobBundle.Consume(); err != nil {
		return nil, err
	}

	return bobSharedKey, nil
}

func decodeX448Key(raw []byte) (x448.Key, error) {
	var key x448.Key
	if len(raw) != len(key) {
		return x448.Key{}, fmt.Errorf("invalid x448 key length: got %d want %d", len(raw), len(key))
	}
	copy(key[:], raw)
	return key, nil
}
