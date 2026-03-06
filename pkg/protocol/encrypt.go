package protocol

import (
	"github.com/slipe-fun/skid/internal/crypto"
	"github.com/slipe-fun/skid/pkg/identity"
)

func Encrypt(content []byte, epoch uint32, senderPrivateKeys *identity.UserPrivate, senderPublicKeys *identity.UserPublic, senderSessionID string, receiverPublicKeys *identity.UserPublic, receiverSessionID string) (*EncryptedMessage, error) {
	ephemeralPubKey, ephemeralPrivKey, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		return nil, err
	}

	resRecv, err := crypto.HybridEncrypt(receiverPublicKeys.ECDHKey, receiverPublicKeys.KyberKey, ephemeralPrivKey, ephemeralPubKey, senderPrivateKeys.ECDHKey, senderPublicKeys.ECDHKey)
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

	kekSalt := GenerateKDFContext(senderSessionID, receiverSessionID, senderPublicKeys, receiverPublicKeys, wrapSaltReceiver)

	kekReceiver, err := crypto.DeriveAesKey(resRecv.SessionKey, kekSalt)
	if err != nil {
		return nil, err
	}

	msg := &EncryptedMessage{
		Version:             CurrentVersion,
		SenderEphemeralECDH: ephemeralPubKey,
		EncapsulatedKey:     resRecv.CipherText,
		CekWrapSalt:         wrapSaltReceiver,
		Epoch:               epoch + 1,
	}

	aad := GenerateAAD(*msg, senderSessionID, receiverSessionID, senderPublicKeys, receiverPublicKeys)

	aadKek := append(aad[:len(aad):len(aad)], []byte("-KEK")...)
	wrappedCekReceiver, wrapIvReceiver, err := crypto.Encrypt(kekReceiver, cekRaw, aadKek)
	if err != nil {
		return nil, err
	}

	msg.CekWrap = wrappedCekReceiver
	msg.CekWrapIV = wrapIvReceiver

	aadCek := append(aad[:len(aad):len(aad)], []byte("-CEK")...)
	ciphertext, iv, err := crypto.Encrypt(cekRaw, content, aadCek)
	if err != nil {
		return nil, err
	}

	msg.Ciphertext = ciphertext
	msg.IV = iv

	return msg, nil
}
