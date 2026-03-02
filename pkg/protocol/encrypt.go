package protocol

import (
	"crypto/ed25519"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Encrypt(content []byte, senderPrivateKeys *identity.UserPrivate, receiverPublicKeys *identity.UserPublic) (*EncryptedMessage, error) {
	resRecv, err := crypto.HybridEncrypt(receiverPublicKeys.ECDHKey, receiverPublicKeys.KyberKey, senderPrivateKeys.ECDHKey)
	if err != nil {
		return nil, err
	}

	cekRaw, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	wrapSaltReceiver, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	kekReceiver, err := crypto.DeriveAesKey(resRecv.SessionKey, wrapSaltReceiver)
	if err != nil {
		return nil, err
	}

	wrappedCekReceiver, wrapIvReceiver, err := crypto.Encrypt(kekReceiver, cekRaw)
	if err != nil {
		return nil, err
	}

	ciphertext, iv, err := crypto.Encrypt(cekRaw, content)
	if err != nil {
		return nil, err
	}

	msg := &EncryptedMessage{
		Version:         CurrentVersion,
		Ciphertext:      ciphertext,
		IV:              iv,
		EncapsulatedKey: resRecv.CipherText,
		CekWrap:         wrappedCekReceiver,
		CekWrapIV:       wrapIvReceiver,
		CekWrapSalt:     wrapSaltReceiver,
	}

	payload, err := msg.signingPayload(receiverPublicKeys)
	if err != nil {
		panic(err)
	}

	msg.Signature = ed25519.Sign(senderPrivateKeys.Ed25519Key, payload)

	return msg, nil
}
