package crypto

import (
	"bytes"
	"testing"
)

func TestAESRoundTrip(t *testing.T) {
	key, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}

	plaintext := []byte("hello, skid")
	aad := []byte("aad")

	ciphertext, iv, err := Encrypt(key, plaintext, aad)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := Decrypt(key, ciphertext, iv, aad)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %x want %x", got, plaintext)
	}
}

func TestAESDecryptRejectsInvalidIVLength(t *testing.T) {
	key, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}

	if _, err := Decrypt(key, []byte("cipher"), []byte("short"), []byte("aad")); err == nil {
		t.Fatal("expected invalid IV length error")
	}
}

func TestAESDecryptRejectsTamperedCiphertext(t *testing.T) {
	key, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}

	ciphertext, iv, err := Encrypt(key, []byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	ciphertext[0] ^= 0xFF

	if _, err := Decrypt(key, ciphertext, iv, []byte("aad")); err == nil {
		t.Fatal("expected tampered ciphertext to fail decryption")
	}
}

func TestAESDecryptRejectsWrongAAD(t *testing.T) {
	key, err := RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}

	ciphertext, iv, err := Encrypt(key, []byte("hello"), []byte("aad-1"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if _, err := Decrypt(key, ciphertext, iv, []byte("aad-2")); err == nil {
		t.Fatal("expected wrong AAD to fail decryption")
	}
}
