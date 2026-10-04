package ssmproto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestMessageRoundTrip(t *testing.T) {
	m := NewMessage(MsgInputStreamData, 42, HeaderFlagData, PayloadOutput, []byte("hello"))
	raw := m.Marshal()
	if got := len(raw); got != 120+5 {
		t.Fatalf("encoded length = %d, want 125", got)
	}
	if got := string(raw[4:36]); got != "input_stream_data"+strings.Repeat(" ", 15) {
		t.Fatalf("message type field = %q", got)
	}
	out, err := UnmarshalMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	if out.MessageType != m.MessageType || out.SequenceNumber != 42 || out.MessageID != m.MessageID ||
		out.PayloadType != PayloadOutput || string(out.Payload) != "hello" || out.CreatedDate != m.CreatedDate {
		t.Fatalf("round trip mismatch: %+v vs %+v", out, m)
	}

	raw[len(raw)-1] ^= 0xff
	if _, err := UnmarshalMessage(raw); err == nil {
		t.Fatal("corrupted payload passed digest validation")
	}
}

func TestUUIDLayout(t *testing.T) {
	// The protocol writes the least significant 8 bytes first.
	id := uuid.MustParse("00112233-4455-6677-8899-aabbccddeeff")
	b := make([]byte, 16)
	putUUID(b, id)
	want := []byte{0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77}
	if !bytes.Equal(b, want) {
		t.Fatalf("putUUID = %x, want %x", b, want)
	}
	if getUUID(b) != id {
		t.Fatal("getUUID did not invert putUUID")
	}
}

func TestEncrypterRoundTrip(t *testing.T) {
	key := make([]byte, 64)
	_, _ = rand.Read(key)
	client, _ := NewEncrypter(key, nil)
	agent, _ := NewEncrypter(append(append([]byte{}, key[32:]...), key[:32]...), nil)
	ct, err := client.Encrypt([]byte("up"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := agent.Decrypt(ct); err != nil || string(pt) != "up" {
		t.Fatalf("agent decrypt: %q %v", pt, err)
	}
	ct, _ = agent.Encrypt([]byte("down"))
	if pt, err := client.Decrypt(ct); err != nil || string(pt) != "down" {
		t.Fatalf("client decrypt: %q %v", pt, err)
	}
}
