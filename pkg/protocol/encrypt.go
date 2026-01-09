package protocol

import (
	"crypto/ed25519"

	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

type EncryptedMessage struct {
	Ciphertext            []byte
	IV                    []byte
	EncapsulatedKey       []byte
	WrappedCekReceiver    []byte
	WrapIVReceiver        []byte
	WrapSaltReceiver      []byte
	EncapsulatedKeySender []byte
	WrappedCekSender      []byte
	WrapIVSender          []byte
	WrapSaltSender        []byte
	Signature             []byte
}

func Encrypt(content string, senderPublicKeys *identity.UserPublic, senderPrivateKeys *identity.UserPrivate, receiverPublicKeys *identity.UserPublic) (*EncryptedMessage, error) {
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

	resSender, err := crypto.HybridEncrypt(senderPublicKeys.ECDHKey, senderPublicKeys.KyberKey, senderPrivateKeys.ECDHKey)
	if err != nil {
		return nil, err
	}

	wrapSaltSender, err := crypto.RandomBytes(32)
	if err != nil {
		return nil, err
	}

	kekSender, err := crypto.DeriveAesKey(resSender.SessionKey, wrapSaltSender)
	wrappedCekSender, wrapIVSender, err := crypto.Encrypt(kekSender, cekRaw)
	if err != nil {
		return nil, err
	}

	ciphertext, iv, err := crypto.Encrypt(cekRaw, []byte(content))
	if err != nil {
		return nil, err
	}

	signature := ed25519.Sign(senderPrivateKeys.Ed25519Key, ciphertext)

	return &EncryptedMessage{
		Ciphertext:            ciphertext,
		IV:                    iv,
		EncapsulatedKey:       resRecv.CipherText,
		WrappedCekReceiver:    wrappedCekReceiver,
		WrapIVReceiver:        wrapIvReceiver,
		WrapSaltReceiver:      wrapSaltReceiver,
		EncapsulatedKeySender: resSender.CipherText,
		WrappedCekSender:      wrappedCekSender,
		WrapIVSender:          wrapIVSender,
		WrapSaltSender:        wrapSaltSender,
		Signature:             signature,
	}, nil
}
