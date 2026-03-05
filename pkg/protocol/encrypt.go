package protocol

import (
	"crypto/ed25519"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Encrypt(content []byte, epoch uint32, senderPrivateKeys *identity.UserPrivate, senderPublicKeys *identity.UserPublic, senderSessionID string, receiverPublicKeys *identity.UserPublic, receiverSessionID string) (*EncryptedMessage, error) {
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

	msg := &EncryptedMessage{
		Version:         CurrentVersion,
		EncapsulatedKey: resRecv.CipherText,
		CekWrapSalt:     wrapSaltReceiver,
		Epoch:           epoch + 1,
	}

	aad := GenerateAAD(*msg, senderSessionID, receiverSessionID, senderPublicKeys, receiverPublicKeys)

	aadKek := append(aad, []byte("-KEK")...)
	wrappedCekReceiver, wrapIvReceiver, err := crypto.Encrypt(kekReceiver, cekRaw, aadKek)
	if err != nil {
		return nil, err
	}

	msg.CekWrap = wrappedCekReceiver
	msg.CekWrapIV = wrapIvReceiver

	aadCek := append(aad, []byte("-CEK")...)
	ciphertext, iv, err := crypto.Encrypt(cekRaw, content, aadCek)
	if err != nil {
		return nil, err
	}

	msg.Ciphertext = ciphertext
	msg.IV = iv

	payload, err := msg.signingPayload(senderPublicKeys, receiverPublicKeys, []byte(receiverSessionID), []byte(senderSessionID))
	if err != nil {
		return nil, err
	}

	msg.Signature = ed25519.Sign(senderPrivateKeys.Ed25519Key, payload)

	return msg, nil
}
