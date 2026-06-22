package storage_test

import (
	"bytes"
	"testing"

	"github.com/BeaverMail/beaver/internal/storage"
)

func TestAppendEnvelopeRoundtripPlain(t *testing.T) {
	t.Parallel()

	raw := []byte{0x01, 0x02, 0x03, 0x04}
	wire, err := storage.AppendEnvelope(nil, 7, raw)
	if err != nil {
		t.Fatal(err)
	}
	if wire[4] != storage.FlagPlain {
		t.Fatalf("flags: got %#x want %#x", wire[4], storage.FlagPlain)
	}
	got, err := storage.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("payload: got % x want % x", got, raw)
	}
}

func TestAppendEnvelopeRoundtripLZ4(t *testing.T) {
	t.Parallel()

	raw := bytes.Repeat([]byte{0xAB}, storage.CompressThreshold)
	wire, err := storage.AppendEnvelope(nil, 2, raw)
	if err != nil {
		t.Fatal(err)
	}
	if wire[4] != storage.FlagLZ4 {
		t.Fatalf("flags: got %#x want %#x", wire[4], storage.FlagLZ4)
	}
	got, err := storage.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, raw) {
		t.Fatalf("payload len %d want %d", len(got), len(raw))
	}
}

func TestAppendEnvelopeHeaderLayout(t *testing.T) {
	t.Parallel()

	raw := []byte{0xAA}
	wire, err := storage.AppendEnvelope(nil, 0x0A, raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) < storage.EnvelopeHeaderLen+1 {
		t.Fatalf("wire too short: %d", len(wire))
	}
	if wire[0] != storage.Magic0 || wire[1] != storage.Magic1 {
		t.Fatalf("magic: got % x", wire[:2])
	}
	if wire[2] != 0x0A {
		t.Errorf("version: got %#x", wire[2])
	}
	if wire[3] != storage.FormatMsgpack {
		t.Errorf("format: got %#x", wire[3])
	}
	if wire[4] != storage.FlagPlain {
		t.Errorf("flags: got %#x", wire[4])
	}
	if !bytes.Equal(wire[storage.EnvelopeHeaderLen:], raw) {
		t.Errorf("payload mismatch")
	}
}

func TestDecodeEnvelopeErrors(t *testing.T) {
	t.Parallel()

	raw := []byte{0x01, 0x02}
	wire, err := storage.AppendEnvelope(nil, 1, raw)
	if err != nil {
		t.Fatal(err)
	}

	_, err = storage.DecodeEnvelope(wire[:storage.EnvelopeHeaderLen-1])
	if err != storage.ErrEnvelopeTooShort {
		t.Fatalf("short: got %v want %v", err, storage.ErrEnvelopeTooShort)
	}

	badMagic := append([]byte(nil), wire...)
	badMagic[0] = 0x00
	_, err = storage.DecodeEnvelope(badMagic)
	if err != storage.ErrInvalidMagic {
		t.Fatalf("magic: got %v want %v", err, storage.ErrInvalidMagic)
	}

	badFormat := append([]byte(nil), wire...)
	badFormat[3] = 0xFF
	_, err = storage.DecodeEnvelope(badFormat)
	if err != storage.ErrInvalidFormat {
		t.Fatalf("format: got %v want %v", err, storage.ErrInvalidFormat)
	}

	badHash := append([]byte(nil), wire...)
	badHash[storage.EnvelopeHeaderLen] ^= 0xFF
	_, err = storage.DecodeEnvelope(badHash)
	if err != storage.ErrHashMismatch {
		t.Fatalf("hash: got %v want %v", err, storage.ErrHashMismatch)
	}

	unknownFlag := append([]byte(nil), wire...)
	unknownFlag[4] = 0x02
	_, err = storage.DecodeEnvelope(unknownFlag)
	if err != storage.ErrUnknownFlag {
		t.Fatalf("flag: got %v want %v", err, storage.ErrUnknownFlag)
	}
}

func TestAppendEnvelopeReusesBuffer(t *testing.T) {
	t.Parallel()

	buf := make([]byte, 0, storage.DefaultBufCap)
	origCap := cap(buf)
	raw := []byte{0x01, 0x02, 0x03}

	for i := 0; i < 50; i++ {
		buf = buf[:0]
		var err error
		buf, err = storage.AppendEnvelope(buf, byte(i), raw)
		if err != nil {
			t.Fatal(err)
		}
		if cap(buf) != origCap {
			t.Fatalf("iteration %d: cap grew %d -> %d", i, origCap, cap(buf))
		}
	}
}

func TestMarshalPersistRoundtrip(t *testing.T) {
	t.Parallel()

	type record struct {
		MailboxID uint32 `msgpack:"mb"`
		Flags     uint32 `msgpack:"fl"`
	}

	want := record{MailboxID: 42, Flags: 0x0F}
	wire, err := storage.MarshalPersist(nil, 3, want)
	if err != nil {
		t.Fatal(err)
	}

	var got record
	if err := storage.UnmarshalPersist(wire, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v want %+v", got, want)
	}
}

func TestMarshalPersistLZ4Threshold(t *testing.T) {
	t.Parallel()

	type blob struct {
		Data []byte `msgpack:"d"`
	}
	want := blob{Data: bytes.Repeat([]byte{'z'}, storage.CompressThreshold)}
	wire, err := storage.MarshalPersist(nil, 1, want)
	if err != nil {
		t.Fatal(err)
	}
	if wire[4] != storage.FlagLZ4 {
		t.Fatalf("flags: got %#x want LZ4", wire[4])
	}

	var got blob
	if err := storage.UnmarshalPersist(wire, &got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Data, want.Data) {
		t.Fatalf("data len %d want %d", len(got.Data), len(want.Data))
	}
}
