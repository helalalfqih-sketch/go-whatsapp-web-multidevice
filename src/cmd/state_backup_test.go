package cmd

import (
	"bytes"
	"testing"
)

func TestStateEncryptionRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x42}, 32)
	plain := []byte("gowa persistent state")

	blob, err := encryptState(plain, key)
	if err != nil {
		t.Fatalf("encryptState: %v", err)
	}
	if bytes.Equal(blob, plain) {
		t.Fatal("encrypted state must not equal plaintext")
	}

	got, err := decryptState(blob, key)
	if err != nil {
		t.Fatalf("decryptState: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch: got %q want %q", got, plain)
	}
}

func TestStateEncryptionRejectsTampering(t *testing.T) {
	key := bytes.Repeat([]byte{0x24}, 32)
	blob, err := encryptState([]byte("sensitive"), key)
	if err != nil {
		t.Fatalf("encryptState: %v", err)
	}
	blob[len(blob)-1] ^= 0xff
	if _, err := decryptState(blob, key); err == nil {
		t.Fatal("tampered ciphertext must be rejected")
	}
}

func TestSQLitePathFromURI(t *testing.T) {
	tests := map[string]string{
		"file:storages/whatsapp.db":                         "storages/whatsapp.db",
		"file:storages/oauth.db?_foreign_keys=on":          "storages/oauth.db",
		"postgres://user:pass@example.test/db":             "",
		"":                                                  "",
	}
	for input, want := range tests {
		if got := sqlitePathFromURI(input); got != want {
			t.Errorf("sqlitePathFromURI(%q)=%q want %q", input, got, want)
		}
	}
}
