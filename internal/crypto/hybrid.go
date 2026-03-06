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

func HybridEncrypt(receiverECDHPublic, receiverKyberPublic, senderECDHEphemeralPrivate, senderECDHEphemeralPublic, senderECDHStaticPrivate, senderECDHStaticPublic []byte) (*HybridResult, error) {
	ecdhEphemeralSS, err := DeriveECDHSharedSecret(senderECDHEphemeralPrivate, receiverECDHPublic)
	if err != nil {
		return nil, err
	}

	ecdhStaticSS, err := DeriveECDHSharedSecret(senderECDHStaticPrivate, receiverECDHPublic)
	if err != nil {
		return nil, err
	}

	kyberCT, kyberSS, err := EncapsulateKyber(receiverKyberPublic)
	if err != nil {
		return nil, err
	}

	ikm := make([]byte, 0, len(kyberSS)+len(ecdhEphemeralSS)+len(ecdhStaticSS))
	ikm = append(ikm, kyberSS...)
	ikm = append(ikm, ecdhEphemeralSS...)
	ikm = append(ikm, ecdhStaticSS...)

	info := AppendWithLength(senderECDHEphemeralPublic, senderECDHStaticPublic, receiverECDHPublic, receiverKyberPublic, kyberCT)
	kdf := hkdf.New(sha256.New, ikm, nil, info)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	return &HybridResult{
		SessionKey: sessionKey,
		CipherText: kyberCT,
	}, nil
}

func HybridDecrypt(senderECDHEphemeralPublic, senderECDHStaticPublic, receiverECDHPrivate, receiverECDHPublic, receiverKyberPrivate, receiverKyberPublic, kyberCT []byte) ([]byte, error) {
	ecdhEphemeralSS, err := DeriveECDHSharedSecret(receiverECDHPrivate, senderECDHEphemeralPublic)
	if err != nil {
		return nil, err
	}

	ecdhStaticSS, err := DeriveECDHSharedSecret(receiverECDHPrivate, senderECDHStaticPublic)
	if err != nil {
		return nil, err
	}

	kyberSS, err := DecapsulateKyber(receiverKyberPrivate, kyberCT)
	if err != nil {
		return nil, err
	}

	ikm := make([]byte, 0, len(kyberSS)+len(ecdhEphemeralSS)+len(ecdhStaticSS))
	ikm = append(ikm, kyberSS...)
	ikm = append(ikm, ecdhEphemeralSS...)
	ikm = append(ikm, ecdhStaticSS...)

	info := AppendWithLength(senderECDHEphemeralPublic, senderECDHStaticPublic, receiverECDHPublic, receiverKyberPublic, kyberCT)
	kdf := hkdf.New(sha256.New, ikm, nil, info)

	sessionKey := make([]byte, 32)
	if _, err := io.ReadFull(kdf, sessionKey); err != nil {
		return nil, err
	}

	return sessionKey, nil
}
