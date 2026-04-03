package identity

import (
	"bytes"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"
)

func TestNewPreKeyBundleProducesVerifiableSignature(t *testing.T) {
	publicDevice, privateDevice, err := NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}

	publicBundle, privateBundle, err := NewPreKeyBundle(publicDevice, privateDevice)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}

	if len(privateBundle.IK_Priv) == 0 || len(privateBundle.SPK_Priv) == 0 || len(privateBundle.OPK_Priv) == 0 || len(privateBundle.Kyber768_Priv) == 0 {
		t.Fatal("expected private bundle keys to be populated")
	}

	if !bytes.Equal(publicBundle.Signature_Pub, publicDevice.SignatureKey) {
		t.Fatal("bundle signature public key does not match device public signing key")
	}

	if !ed448.Verify(publicDevice.SignatureKey, BuildPrekeyBundleHash(publicBundle), publicBundle.Signature, PrekeyBundleDomainPrefix) {
		t.Fatal("bundle signature verification failed")
	}
}

func TestPreKeyBundleSignatureBreaksOnTamper(t *testing.T) {
	publicDevice, privateDevice, err := NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}

	publicBundle, _, err := NewPreKeyBundle(publicDevice, privateDevice)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}

	tampered := *publicBundle
	tampered.Kyber768_Pub = append([]byte(nil), publicBundle.Kyber768_Pub...)
	tampered.Kyber768_Pub[0] ^= 0xFF

	if ed448.Verify(publicDevice.SignatureKey, BuildPrekeyBundleHash(&tampered), tampered.Signature, PrekeyBundleDomainPrefix) {
		t.Fatal("tampered bundle should not verify")
	}
}

func TestGeneratePrekeyBundleMessageIsStableAndDomainSeparated(t *testing.T) {
	publicDevice, privateDevice, err := NewDevice()
	if err != nil {
		t.Fatalf("NewDevice: %v", err)
	}

	publicBundle, _, err := NewPreKeyBundle(publicDevice, privateDevice)
	if err != nil {
		t.Fatalf("NewPreKeyBundle: %v", err)
	}

	msg1 := GeneratePrekeyBundleMessage(publicBundle)
	msg2 := GeneratePrekeyBundleMessage(publicBundle)

	if !bytes.Equal(msg1, msg2) {
		t.Fatal("GeneratePrekeyBundleMessage should be deterministic")
	}

	if !bytes.HasPrefix(msg1, []byte(PrekeyBundleDomainPrefix)) {
		t.Fatal("bundle message should start with domain prefix")
	}

	if len(BuildPrekeyBundleHash(publicBundle)) != 32 {
		t.Fatal("bundle hash should be 32 bytes")
	}
}
