// Package storage defines the KV persistence layer (keys, envelope, codec).
//
// Design notes (see .specs/storage.md):
//
//   - Store: every method on the Store interface takes context.Context (Postgres
//     timeouts, Redis locks in M2, graceful shutdown). MarshalPersist / UnmarshalPersist
//     are local CPU and do not take ctx.
//
//   - Keys: prefer AppendKey(buf, ...) over MakeKey(...) so hot paths reuse a []byte
//     buffer instead of allocating 10+ byte keys on every call (see key.go).
//
//   - Buffers: Batch, Iterate scanners, and Store drivers should own pre-allocated
//     slices (e.g. make([]byte, 0, DefaultBufCap)). Passing []byte is cheap (slice
//     header only); resetting with buf = buf[:0] before AppendKey keeps write hot paths
//     allocation-free when capacity suffices.
package storage

import "github.com/vmihailenco/msgpack/v5"

// DefaultBufCap is the initial capacity for reusable key/value buffers in Batch and Store I/O.
const DefaultBufCap = 1024

// Envelope wire constants (header: magic[2] version format flags hash[4] payload).
const (
	Magic0            byte = 0xBE // "Beaver"
	Magic1            byte = 0x4D // "Mail"
	FormatMsgpack     byte = 1
	FlagPlain         byte = 0x00 // plaintext msgpack
	FlagLZ4           byte = 0x01 // LZ4-compressed payload
	CompressThreshold      = 4096 // compress when raw msgpack >= 4 KiB
)

// Blake3DigestLen is the size of a raw Blake3 hash stored in KV blob pointers.
const Blake3DigestLen = 32

// MarshalPersist msgpack-encodes v and appends a wire envelope to buf.
func MarshalPersist(buf []byte, version byte, v any) ([]byte, error) {
	raw, err := msgpack.Marshal(v)
	if err != nil {
		return nil, err
	}
	return AppendEnvelope(buf, version, raw)
}

// UnmarshalPersist decodes an envelope and msgpack-decodes into v.
func UnmarshalPersist(data []byte, v any) error {
	raw, err := DecodeEnvelope(data)
	if err != nil {
		return err
	}
	return msgpack.Unmarshal(raw, v)
}
