package plugin

import (
	"encoding/json"
	"fmt"
	"io"
)

// BatchEmitter writes JSONL protocol events to w (typically stdout).
type BatchEmitter struct {
	w         io.Writer
	batchSize int
	pending   []BatchMessage
}

// NewBatchEmitter creates an emitter with the given batch flush threshold.
func NewBatchEmitter(w io.Writer, batchSize int) *BatchEmitter {
	if batchSize < 1 {
		batchSize = DefaultBatchSize
	}
	return &BatchEmitter{w: w, batchSize: batchSize}
}

// Add queues a message and flushes when the batch is full.
func (e *BatchEmitter) Add(msg BatchMessage) error {
	e.pending = append(e.pending, msg)
	if len(e.pending) >= e.batchSize {
		return e.Flush()
	}
	return nil
}

// Flush writes a batch event if pending messages exist.
func (e *BatchEmitter) Flush() error {
	if len(e.pending) == 0 {
		return nil
	}
	ev := CliEvent{Op: CliOpBatch, Messages: e.pending}
	if err := e.write(ev); err != nil {
		return err
	}
	e.pending = e.pending[:0]
	return nil
}

// EmitDone flushes pending batches and sends the final done event.
func (e *BatchEmitter) EmitDone() error {
	if err := e.Flush(); err != nil {
		return err
	}
	return e.write(CliEvent{Op: CliOpDone})
}

// EmitError sends a fatal error event.
func (e *BatchEmitter) EmitError(message string) error {
	if err := e.Flush(); err != nil {
		return err
	}
	return e.write(CliEvent{Op: CliOpError, Message: message})
}

func (e *BatchEmitter) write(ev CliEvent) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(e.w, "%s\n", b)
	return err
}
