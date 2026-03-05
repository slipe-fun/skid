package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Decrypt(encrypted *EncryptedMessage, epoch uint32, receiverPrivateKeys *identity.UserPrivate, receiverPublicKeys *identity.UserPublic, receiverSessionID string, senderPublicKeys *identity.UserPublic, senderSessionID string) ([]byte, error) {
	switch encrypted.Version {
	case 1:
		payload, err := encrypted.signingPayload(senderPublicKeys, receiverPublicKeys, []byte(receiverSessionID), []byte(senderSessionID))
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

		aad := GenerateAAD(*encrypted, senderSessionID, receiverSessionID, senderPublicKeys, receiverPublicKeys)

		aadKek := append(aad, []byte("-KEK")...)
		cek, err := crypto.Decrypt(kekReceiver, encrypted.CekWrap, encrypted.CekWrapIV, aadKek)
		if err != nil {
			return nil, err
		}

		aadCek := append(aad, []byte("-CEK")...)
		plaintext, err := crypto.Decrypt(cek, encrypted.Ciphertext, encrypted.IV, aadCek)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	default:
		return nil, fmt.Errorf("unknown protocol version: %d", encrypted.Version)
	}
}
