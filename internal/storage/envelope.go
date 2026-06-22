// Envelope wire format for KV values: magic, metadata, integrity hash, payload.
package storage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"

	"github.com/pierrec/lz4/v4"
	"github.com/zeebo/xxh3"
)

// EnvelopeHeaderLen is the fixed header size before payload.
const EnvelopeHeaderLen = 9

var (
	ErrEnvelopeTooShort = errors.New("storage: envelope shorter than header")
	ErrInvalidMagic     = errors.New("storage: invalid envelope magic")
	ErrInvalidFormat    = errors.New("storage: unsupported envelope format")
	ErrUnknownFlag      = errors.New("storage: unknown envelope flag")
	ErrHashMismatch     = errors.New("storage: envelope hash mismatch")
)

// AppendEnvelope appends a wire envelope around raw msgpack to buf.
// Payloads >= CompressThreshold are LZ4-compressed (frame format) before hashing.
func AppendEnvelope(buf []byte, version byte, rawMsgpack []byte) ([]byte, error) {
	payload, flags, err := preparePayload(rawMsgpack)
	if err != nil {
		return nil, err
	}
	hash := payloadHash(payload)

	buf = append(buf, Magic0, Magic1, version, FormatMsgpack, flags)
	var hb [4]byte
	binary.BigEndian.PutUint32(hb[:], hash)
	buf = append(buf, hb[:]...)
	buf = append(buf, payload...)
	return buf, nil
}

// DecodeEnvelope validates the envelope and returns the raw msgpack payload.
func DecodeEnvelope(data []byte) ([]byte, error) {
	if len(data) < EnvelopeHeaderLen {
		return nil, ErrEnvelopeTooShort
	}
	if data[0] != Magic0 || data[1] != Magic1 {
		return nil, ErrInvalidMagic
	}
	if data[3] != FormatMsgpack {
		return nil, ErrInvalidFormat
	}

	flags := data[4]
	wantHash := binary.BigEndian.Uint32(data[5:9])
	payload := data[EnvelopeHeaderLen:]

	if payloadHash(payload) != wantHash {
		return nil, ErrHashMismatch
	}

	switch flags {
	case FlagPlain:
		return payload, nil
	case FlagLZ4:
		return decompressLZ4(payload)
	default:
		return nil, ErrUnknownFlag
	}
}

// preparePayload returns wire payload bytes and the flags byte for the envelope.
func preparePayload(rawMsgpack []byte) (payload []byte, flags byte, err error) {
	if len(rawMsgpack) < CompressThreshold {
		return rawMsgpack, FlagPlain, nil
	}
	compressed, err := compressLZ4(rawMsgpack)
	if err != nil {
		return nil, 0, err
	}
	return compressed, FlagLZ4, nil
}

// payloadHash returns the lower 32 bits of XXH3-64 (xxh3-32 digest field per spec).
func payloadHash(payload []byte) uint32 {
	return uint32(xxh3.Hash(payload))
}

// compressLZ4 wraps src in an LZ4 frame (self-describing length for decode).
func compressLZ4(src []byte) ([]byte, error) {
	var out bytes.Buffer
	w := lz4.NewWriter(&out)
	if _, err := w.Write(src); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// decompressLZ4 expands an LZ4 frame produced by compressLZ4.
func decompressLZ4(src []byte) ([]byte, error) {
	r := lz4.NewReader(bytes.NewReader(src))
	return io.ReadAll(r)
}
