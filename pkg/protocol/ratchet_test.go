package protocol

import (
	"bytes"
	"strings"
	"testing"

	intcrypto "github.com/slipe-fun/skid/internal/crypto"
)

func newTestSessions(t *testing.T) (*Session, *Session, []byte, []byte) {
	t.Helper()

	sharedKey, err := intcrypto.RandomBytes(32)
	if err != nil {
		t.Fatalf("RandomBytes: %v", err)
	}

	aliceIKPub, _, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(aliceIK): %v", err)
	}

	bobIKPub, bobIKPriv, err := intcrypto.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair(bobIK): %v", err)
	}

	alice, err := NewSessionInitiator(sharedKey, bobIKPub)
	if err != nil {
		t.Fatalf("NewSessionInitiator: %v", err)
	}

	bob := NewSessionResponder(sharedKey, bobIKPriv)

	return alice, bob, append([]byte(nil), aliceIKPub[:]...), append([]byte(nil), bobIKPub[:]...)
}

func TestGenerateAADIsOrderIndependentForIdentities(t *testing.T) {
	message := &RatchetMessage{
		Version:    CurrentVersion,
		Type:       MessageTypeRatchet,
		SessionID:  []byte("sid"),
		RatchetPub: bytes.Repeat([]byte{0xAA}, 56),
		Index:      7,
		PrevIdx:    3,
	}

	aliceIK := bytes.Repeat([]byte{0x01}, 56)
	bobIK := bytes.Repeat([]byte{0x02}, 56)

	aad1 := GenerateAAD(message, aliceIK, bobIK)
	aad2 := GenerateAAD(message, bobIK, aliceIK)

	if !bytes.Equal(aad1, aad2) {
		t.Fatal("AAD should be stable regardless of identity argument order")
	}
}

func TestKDFOutputsExpectedLengths(t *testing.T) {
	newRK, newCK := kdfRK(bytes.Repeat([]byte{0x01}, 32), bytes.Repeat([]byte{0x02}, 56))
	if len(newRK) != 32 || len(newCK) != 32 {
		t.Fatalf("unexpected root/chain key lengths: rk=%d ck=%d", len(newRK), len(newCK))
	}

	nextCK, msgKey := kdfCK(newCK)
	if len(nextCK) != 32 || len(msgKey) != 32 {
		t.Fatalf("unexpected chain/message key lengths: ck=%d mk=%d", len(nextCK), len(msgKey))
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	plaintext := []byte("hello")
	message, err := alice.Encrypt(plaintext, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	got, err := bob.Decrypt(message, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %x want %x", got, plaintext)
	}
}

func TestEncryptSetsRatchetMessageMetadata(t *testing.T) {
	alice, _, aliceIK, bobIK := newTestSessions(t)

	message, err := alice.Encrypt([]byte("hello"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if message.Version != CurrentVersion || message.Type != MessageTypeRatchet {
		t.Fatal("unexpected message metadata")
	}
	if message.Index != 0 || message.PrevIdx != 0 {
		t.Fatalf("unexpected initial indexes: idx=%d prev=%d", message.Index, message.PrevIdx)
	}
	if len(message.RatchetPub) != 56 {
		t.Fatalf("unexpected ratchet pub length: %d", len(message.RatchetPub))
	}
	if len(message.Nonce) != 12 {
		t.Fatalf("unexpected nonce length: %d", len(message.Nonce))
	}
}

func TestResponderCannotEncryptBeforeInitialization(t *testing.T) {
	_, bob, aliceIK, bobIK := newTestSessions(t)

	if _, err := bob.Encrypt([]byte("hello"), aliceIK, bobIK); err == nil || !strings.Contains(err.Error(), "not fully initialized") {
		t.Fatalf("expected uninitialized responder error, got %v", err)
	}
}

func TestBobReplyTriggersRatchetStep(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	first, err := alice.Encrypt([]byte("hello bob"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(first): %v", err)
	}

	if _, err := bob.Decrypt(first, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(first): %v", err)
	}

	reply, err := bob.Encrypt([]byte("hello alice"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(reply): %v", err)
	}

	got, err := alice.Decrypt(reply, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Decrypt(reply): %v", err)
	}

	if !bytes.Equal(got, []byte("hello alice")) {
		t.Fatalf("reply plaintext mismatch: got %q", got)
	}
}

func TestOutOfOrderMessagesUseSkippedKeys(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	firstPlain := []byte("first")
	secondPlain := []byte("second")

	firstMsg, err := alice.Encrypt(firstPlain, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(first): %v", err)
	}
	secondMsg, err := alice.Encrypt(secondPlain, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(second): %v", err)
	}

	gotSecond, err := bob.Decrypt(secondMsg, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Decrypt(second): %v", err)
	}
	if !bytes.Equal(gotSecond, secondPlain) {
		t.Fatalf("second plaintext mismatch: got %q", gotSecond)
	}
	if len(bob.skippedKeys) != 1 {
		t.Fatalf("expected one skipped key, got %d", len(bob.skippedKeys))
	}

	gotFirst, err := bob.Decrypt(firstMsg, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Decrypt(first): %v", err)
	}
	if !bytes.Equal(gotFirst, firstPlain) {
		t.Fatalf("first plaintext mismatch: got %q", gotFirst)
	}
	if len(bob.skippedKeys) != 0 {
		t.Fatalf("expected skipped keys to be consumed, got %d", len(bob.skippedKeys))
	}
}

func TestDecryptRejectsNilMessage(t *testing.T) {
	_, bob, aliceIK, bobIK := newTestSessions(t)

	if _, err := bob.Decrypt(nil, aliceIK, bobIK); err == nil || !strings.Contains(err.Error(), "nil message") {
		t.Fatalf("expected nil message error, got %v", err)
	}
}

func TestDecryptRejectsUnsupportedVersion(t *testing.T) {
	_, bob, aliceIK, bobIK := newTestSessions(t)

	msg := &RatchetMessage{
		Version:    CurrentVersion + 1,
		Type:       MessageTypeRatchet,
		RatchetPub: bytes.Repeat([]byte{0x01}, 56),
	}

	if _, err := bob.Decrypt(msg, aliceIK, bobIK); err == nil || !strings.Contains(err.Error(), "unsupported message version") {
		t.Fatalf("expected unsupported version error, got %v", err)
	}
}

func TestDecryptRejectsUnexpectedType(t *testing.T) {
	_, bob, aliceIK, bobIK := newTestSessions(t)

	msg := &RatchetMessage{
		Version:    CurrentVersion,
		Type:       MessageTypePreKey,
		RatchetPub: bytes.Repeat([]byte{0x01}, 56),
	}

	if _, err := bob.Decrypt(msg, aliceIK, bobIK); err == nil || !strings.Contains(err.Error(), "unexpected message type") {
		t.Fatalf("expected unexpected type error, got %v", err)
	}
}

func TestDecryptRejectsInvalidRatchetPublicKeyLength(t *testing.T) {
	_, bob, aliceIK, bobIK := newTestSessions(t)

	msg := &RatchetMessage{
		Version:    CurrentVersion,
		Type:       MessageTypeRatchet,
		RatchetPub: []byte{1, 2, 3},
	}

	if _, err := bob.Decrypt(msg, aliceIK, bobIK); err == nil || !strings.Contains(err.Error(), "invalid ratchet public key length") {
		t.Fatalf("expected invalid ratchet pub length error, got %v", err)
	}
}

func TestDecryptRejectsWrongIdentityContext(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	msg, err := alice.Encrypt([]byte("hello"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wrongBobIK := append([]byte(nil), bobIK...)
	wrongBobIK[0] ^= 0xFF

	if _, err := bob.Decrypt(msg, aliceIK, wrongBobIK); err == nil {
		t.Fatal("expected AAD mismatch to fail decryption")
	}
}

func TestDecryptRejectsTooManySkippedMessages(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	msg, err := alice.Encrypt([]byte("hello"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	msg.Index = uint32(maxSkipMessagesLimit + 1)

	if _, err := bob.Decrypt(msg, aliceIK, bobIK); err == nil || !strings.Contains(err.Error(), "too many messages to skip") {
		t.Fatalf("expected skip limit error, got %v", err)
	}
}

func TestReplayDoesNotAdvanceReceiveState(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	first, err := alice.Encrypt([]byte("first"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(first): %v", err)
	}
	second, err := alice.Encrypt([]byte("second"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(second): %v", err)
	}

	if _, err := bob.Decrypt(first, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(first): %v", err)
	}
	if _, err := bob.Decrypt(second, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(second): %v", err)
	}

	if _, err := bob.Decrypt(first, aliceIK, bobIK); err == nil || !strings.Contains(err.Error(), "already processed") {
		t.Fatalf("expected replay rejection, got %v", err)
	}

	third, err := alice.Encrypt([]byte("third"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(third): %v", err)
	}

	got, err := bob.Decrypt(third, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Decrypt(third): %v", err)
	}
	if !bytes.Equal(got, []byte("third")) {
		t.Fatalf("third plaintext mismatch: got %q", got)
	}
}

func TestPreviousChainMessagesRemainDecryptableAfterRatchetStep(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	firstFromAlice, err := alice.Encrypt([]byte("a1"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(a1): %v", err)
	}
	if _, err := bob.Decrypt(firstFromAlice, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(a1): %v", err)
	}

	firstFromBob, err := bob.Encrypt([]byte("b1"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(b1): %v", err)
	}
	delayedFromBob, err := bob.Encrypt([]byte("b2"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(b2): %v", err)
	}

	if _, err := alice.Decrypt(firstFromBob, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(b1): %v", err)
	}

	secondFromAlice, err := alice.Encrypt([]byte("a2"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(a2): %v", err)
	}
	if _, err := bob.Decrypt(secondFromAlice, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(a2): %v", err)
	}

	currentFromBob, err := bob.Encrypt([]byte("b3"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(b3): %v", err)
	}
	if _, err := alice.Decrypt(currentFromBob, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(b3): %v", err)
	}

	got, err := alice.Decrypt(delayedFromBob, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Decrypt(delayed b2): %v", err)
	}
	if !bytes.Equal(got, []byte("b2")) {
		t.Fatalf("delayed plaintext mismatch: got %q", got)
	}
}

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	alice, bob, aliceIK, bobIK := newTestSessions(t)

	first, err := alice.Encrypt([]byte("hello"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(first): %v", err)
	}

	if _, err := bob.Decrypt(first, aliceIK, bobIK); err != nil {
		t.Fatalf("Decrypt(first): %v", err)
	}

	snapshot := bob.Snapshot()
	restored := RestoreSession(snapshot)

	reply, err := restored.Encrypt([]byte("reply"), aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Encrypt(reply): %v", err)
	}

	got, err := alice.Decrypt(reply, aliceIK, bobIK)
	if err != nil {
		t.Fatalf("Decrypt(reply): %v", err)
	}

	if !bytes.Equal(got, []byte("reply")) {
		t.Fatalf("reply plaintext mismatch after restore: got %q", got)
	}
}
