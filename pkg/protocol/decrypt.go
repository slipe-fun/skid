package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Decrypt(encrypted *EncryptedMessage, epoch uint32, receiverPrivateKeys *identity.UserPrivate, receiverPublicKeys *identity.UserPublic, receiverID string, senderPublicKeys *identity.UserPublic, senderID string) ([]byte, error) {
	switch encrypted.Version {
	case 1:
		payload, err := encrypted.signingPayload(receiverPublicKeys, []byte(receiverID), []byte(senderID))
		if err != nil {
			return nil, err
		}

		if encrypted.Epoch <= epoch {
			return nil, errors.New("invalid sequence")
		}

		if !ed25519.Verify(senderPublicKeys.Ed25519Key, payload, encrypted.Signature) {
			return nil, errors.New("invalid signature")
		}

		ssReceiver, err := crypto.HybridDecrypt(
			senderPublicKeys.ECDHKey,
			receiverPrivateKeys.ECDHKey,
			receiverPrivateKeys.KyberKey,
			encrypted.EncapsulatedKey,
		)
		if err != nil {
			return nil, err
		}

		kekReceiver, err := crypto.DeriveAesKey(ssReceiver, encrypted.CekWrapSalt)
		if err != nil {
			return nil, err
		}

		cek, err := crypto.Decrypt(kekReceiver, encrypted.CekWrapIV, encrypted.CekWrap, encrypted.EncapsulatedKey)
		if err != nil {
			return nil, err
		}

		plaintext, err := crypto.Decrypt(cek, encrypted.IV, encrypted.Ciphertext, encrypted.EncapsulatedKey)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	default:
		return nil, fmt.Errorf("unknown protocol version: %d", encrypted.Version)
	}
}
