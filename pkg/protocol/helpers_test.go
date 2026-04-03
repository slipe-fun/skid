package protocol

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
	intcrypto "github.com/slipe-fun/skid/internal/crypto"
)

func TestGeneratePrekeyMessageBundleIsStableAndDomainSeparated(t *testing.T) {
	msg := &PreKeyMessage{
		Version:         CurrentVersion,
		Type:            MessageTypePreKey,
		SessionID:       []byte("session"),
		IKPub:           bytes.Repeat([]byte{0x01}, 56),
		EKPub:           bytes.Repeat([]byte{0x02}, 56),
		KyberCiphertext: bytes.Repeat([]byte{0x03}, 32),
	}

	first := GeneratePrekeyMessageBundle(msg)
	second := GeneratePrekeyMessageBundle(msg)

	if !bytes.Equal(first, second) {
		t.Fatal("GeneratePrekeyMessageBundle should be deterministic")
	}

	if !bytes.HasPrefix(first, []byte(PrekeyMessageBundleDomainPrefix)) {
		t.Fatal("prekey message bundle should start with domain prefix")
	}

	if len(BuildPrekeyMessageBundleHash(msg)) != 32 {
		t.Fatal("prekey message bundle hash should be 32 bytes")
	}
}

func TestPrekeyMessageSignatureBreaksOnTamper(t *testing.T) {
	pub, priv, err := intcrypto.GenerateEd448KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd448KeyPair: %v", err)
	}

	msg := &PreKeyMessage{
		Version:         CurrentVersion,
		Type:            MessageTypePreKey,
		SessionID:       []byte("session"),
		IKPub:           bytes.Repeat([]byte{0x01}, 56),
		EKPub:           bytes.Repeat([]byte{0x02}, 56),
		KyberCiphertext: bytes.Repeat([]byte{0x03}, 32),
	}

	sig := ed448.Sign(priv, BuildPrekeyMessageBundleHash(msg), PrekeyMessageBundleDomainPrefix)
	if !ed448.Verify(pub, BuildPrekeyMessageBundleHash(msg), sig, PrekeyMessageBundleDomainPrefix) {
		t.Fatal("expected signature verification to succeed")
	}

	tampered := *msg
	tampered.KyberCiphertext = append([]byte(nil), msg.KyberCiphertext...)
	tampered.KyberCiphertext[0] ^= 0xFF

	if ed448.Verify(pub, BuildPrekeyMessageBundleHash(&tampered), sig, PrekeyMessageBundleDomainPrefix) {
		t.Fatal("tampered prekey message should not verify")
	}
}

func TestPrekeyMessageSignatureBreaksOnEmbeddedMessageTamper(t *testing.T) {
	pub, priv, err := intcrypto.GenerateEd448KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd448KeyPair: %v", err)
	}

	msg := &PreKeyMessage{
		Version:         CurrentVersion,
		Type:            MessageTypePreKey,
		SessionID:       []byte("session"),
		IKPub:           bytes.Repeat([]byte{0x01}, 56),
		EKPub:           bytes.Repeat([]byte{0x02}, 56),
		KyberCiphertext: bytes.Repeat([]byte{0x03}, 32),
		Message: &RatchetMessage{
			Version:    CurrentVersion,
			Type:       MessageTypeRatchet,
			SessionID:  []byte("ratchet-session"),
			RatchetPub: bytes.Repeat([]byte{0x04}, 56),
			Index:      44,
			PrevIdx:    300,
			Nonce:      bytes.Repeat([]byte{0x05}, 12),
			Ciphertext: bytes.Repeat([]byte{0x06}, 24),
		},
	}

	sig := ed448.Sign(priv, BuildPrekeyMessageBundleHash(msg), PrekeyMessageBundleDomainPrefix)
	if !ed448.Verify(pub, BuildPrekeyMessageBundleHash(msg), sig, PrekeyMessageBundleDomainPrefix) {
		t.Fatal("expected signature verification to succeed")
	}

	tampered := *msg
	tamperedMsg := *msg.Message
	tamperedMsg.Index = 300
	tampered.Message = &tamperedMsg

	if ed448.Verify(pub, BuildPrekeyMessageBundleHash(&tampered), sig, PrekeyMessageBundleDomainPrefix) {
		t.Fatal("tampered embedded ratchet message should not verify")
	}
}
