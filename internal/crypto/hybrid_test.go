package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveHybridKeyDeterministic(t *testing.T) {
	input := bytes.Repeat([]byte{0x01}, 56)
	key1 := DeriveHybridKey(input, input, input, input, bytes.Repeat([]byte{0x02}, 32))
	key2 := DeriveHybridKey(input, input, input, input, bytes.Repeat([]byte{0x02}, 32))

	if len(key1) != 32 {
		t.Fatalf("unexpected key length: %d", len(key1))
	}
	if !bytes.Equal(key1, key2) {
		t.Fatal("DeriveHybridKey should be deterministic for identical inputs")
	}
}

func TestDeriveHybridKeyChangesWhenInputChanges(t *testing.T) {
	base := bytes.Repeat([]byte{0x01}, 56)
	key1 := DeriveHybridKey(base, base, base, base, bytes.Repeat([]byte{0x02}, 32))
	key2 := DeriveHybridKey(base, base, base, base, bytes.Repeat([]byte{0x03}, 32))

	if bytes.Equal(key1, key2) {
		t.Fatal("DeriveHybridKey should change when key material changes")
	}
}
