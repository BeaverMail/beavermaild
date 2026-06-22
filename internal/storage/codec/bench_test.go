// Benchmarks comparing msgpack and JSON for storage-shaped structs.
package codec

import (
	"encoding/json"
	"testing"

	"github.com/BeaverMail/beaver/internal/storage"
	"github.com/vmihailenco/msgpack/v5"
)

func sampleEmailMeta() storage.EmailMeta {
	return storage.EmailMeta{
		Version: 1, MailboxID: 42, ThreadID: 7,
		ReceivedAt: 1710000000, Size: 4096, Flags: 1 << 3,
	}
}

func sampleQueueMessage() storage.QueueMessage {
	return storage.QueueMessage{
		Created: 1710000000, ReturnPath: "sender@example.com", Size: 65536,
		Recipients: []storage.QueueRecipient{
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
		var out storage.EmailMeta
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
		var out storage.EmailMeta
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
		var out storage.QueueMessage
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
		var out storage.QueueMessage
		if err := json.Unmarshal(data, &out); err != nil {
			b.Fatal(err)
		}
	}
}
