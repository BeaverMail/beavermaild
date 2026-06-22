// Benchmarks comparing msgpack and JSON for storage-shaped structs.
package codec

import (
	"encoding/json"
	"testing"

	"github.com/vmihailenco/msgpack/v5"
)

// emailMeta is a small persisted metadata record (hot path).
type emailMeta struct {
	Version    uint8  `msgpack:"v" json:"v"`
	MailboxID  uint32 `msgpack:"mb" json:"mb"`
	ThreadID   uint32 `msgpack:"th" json:"th"`
	ReceivedAt int64  `msgpack:"rcv" json:"rcv"`
	Size       uint32 `msgpack:"sz" json:"sz"`
	Flags      uint32 `msgpack:"fl" json:"fl"`
}

// queueMessage approximates a medium SMTP queue record.
type queueMessage struct {
	Created        uint64      `msgpack:"c" json:"c"`
	BlobHash       [32]byte    `msgpack:"bh" json:"bh"`
	ReturnPath     string      `msgpack:"rp" json:"rp"`
	Recipients     []recipient `msgpack:"rc" json:"rc"`
	ReceivedFromIP [16]byte    `msgpack:"ip" json:"ip"`
	Flags          uint64      `msgpack:"fl" json:"fl"`
	Size           uint64      `msgpack:"sz" json:"sz"`
}

type recipient struct {
	Address string `msgpack:"a" json:"a"`
	Retry   uint32 `msgpack:"r" json:"r"`
	Flags   uint64 `msgpack:"f" json:"f"`
}

func sampleEmailMeta() emailMeta {
	return emailMeta{
		Version: 1, MailboxID: 42, ThreadID: 7,
		ReceivedAt: 1710000000, Size: 4096, Flags: 1 << 3,
	}
}

func sampleQueueMessage() queueMessage {
	return queueMessage{
		Created: 1710000000, ReturnPath: "sender@example.com", Size: 65536,
		Recipients: []recipient{
			{Address: "a@example.com", Retry: 1, Flags: 0},
			{Address: "b@example.com", Retry: 2, Flags: 1},
			{Address: "c@example.org", Retry: 0, Flags: 0},
		},
	}
}

func BenchmarkEncodeEmailMetaMsgpack(b *testing.B) {
	m := sampleEmailMeta()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := msgpack.Marshal(&m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeEmailMetaMsgpack(b *testing.B) {
	data, err := msgpack.Marshal(sampleEmailMeta())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		var out emailMeta
		if err := msgpack.Unmarshal(data, &out); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeEmailMetaJSON(b *testing.B) {
	m := sampleEmailMeta()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := json.Marshal(&m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeEmailMetaJSON(b *testing.B) {
	data, err := json.Marshal(sampleEmailMeta())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		var out emailMeta
		if err := json.Unmarshal(data, &out); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeQueueMessageMsgpack(b *testing.B) {
	m := sampleQueueMessage()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := msgpack.Marshal(&m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeQueueMessageMsgpack(b *testing.B) {
	data, err := msgpack.Marshal(sampleQueueMessage())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		var out queueMessage
		if err := msgpack.Unmarshal(data, &out); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncodeQueueMessageJSON(b *testing.B) {
	m := sampleQueueMessage()
	b.ReportAllocs()
	for b.Loop() {
		if _, err := json.Marshal(&m); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDecodeQueueMessageJSON(b *testing.B) {
	data, err := json.Marshal(sampleQueueMessage())
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		var out queueMessage
		if err := json.Unmarshal(data, &out); err != nil {
			b.Fatal(err)
		}
	}
}
