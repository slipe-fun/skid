package crypto

import (
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"
)

type HybridResult struct {
	SessionKey []byte
	CipherText []byte
}

func HybridEncrypt(receiverECDHPublic, receiverKyberPublic, senderECDHPrivate, senderECDHPublic []byte) (*HybridResult, error) {
	ECDHSS, err := DeriveECDHSharedSecret(senderECDHPrivate, receiverECDHPublic)
	if err != nil {
		return nil, err
	}

	kyberCT, kyberSS, err := EncapsulateKyber(receiverKyberPublic)
	if err != nil {
		return nil, err
	}

	inputKeyMaterial := append(kyberSS, ECDHSS...)
	info := AppendWithLength(senderECDHPublic, receiverECDHPublic, receiverKyberPublic, kyberCT)
	kdf := hkdf.New(sha256.New, inputKeyMaterial, nil, info)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	return &HybridResult{
		SessionKey: sessionKey,
		CipherText: kyberCT,
	}, nil
}

func HybridDecrypt(senderECDHPublic, receiverECDHPrivate, receiverECDHPublic, receiverKyberPrivate, receiverKyberPublic, kyberCT []byte) ([]byte, error) {
	ECDHSS, err := DeriveECDHSharedSecret(receiverECDHPrivate, senderECDHPublic)
	if err != nil {
		return nil, err
	}

	kyberSS, err := DecapsulateKyber(receiverKyberPrivate, kyberCT)
	if err != nil {
		return nil, err
	}

	inputKeyMaterial := append(kyberSS, ECDHSS...)
	info := AppendWithLength(senderECDHPublic, receiverECDHPublic, receiverKyberPublic, kyberCT)
	kdf := hkdf.New(sha256.New, inputKeyMaterial, nil, info)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	return sessionKey, nil
}
