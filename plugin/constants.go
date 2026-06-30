// Package plugin is the public SDK for BeaverMail extension executables.
package plugin

// APIVersion is the CLI JSONL protocol version (bump on breaking changes).
const APIVersion uint32 = 2

// DefaultBatchSize is the default JSONL batch chunk size for CLI plugins.
const DefaultBatchSize = 1000

// EnvBatchSize overrides DefaultBatchSize when set to a positive integer.
const EnvBatchSize = "BEAVER_CLI_BATCH_SIZE"
