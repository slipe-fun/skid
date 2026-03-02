package protocol

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Decrypt(encrypted *EncryptedMessage, receiverPrivateKeys *identity.UserPrivate, receiverPublicKeys *identity.UserPublic, senderPublicKeys *identity.UserPublic) ([]byte, error) {
	switch encrypted.Version {
	case 1:
		payload, err := encrypted.signingPayload(receiverPublicKeys)
		if err != nil {
			panic(err)
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

		cek, err := crypto.Decrypt(kekReceiver, encrypted.CekWrapIV, encrypted.CekWrap)
		if err != nil {
			return nil, err
		}

		plaintext, err := crypto.Decrypt(cek, encrypted.IV, encrypted.Ciphertext)
		if err != nil {
			return nil, err
		}

		return plaintext, nil
	default:
		return nil, fmt.Errorf("unknown protocol version: %d", encrypted.Version)
	}
}
