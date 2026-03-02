package protocol

import (
	"crypto/ed25519"
	"errors"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Decrypt(encrypted *EncryptedMessage, receiverPrivateKeys *identity.UserPrivate, senderPublicKeys *identity.UserPublic) ([]byte, error) {
	if !ed25519.Verify(senderPublicKeys.Ed25519Key, encrypted.Ciphertext, encrypted.Signature) {
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
}
