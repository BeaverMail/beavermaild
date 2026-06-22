// Subspace identifiers: one SQL table per letter in M1.
package storage

// M1 subspace bytes (one KV table per value).
const (
	SubspaceMail    byte = 'm' // mail / document properties
	SubspaceIndex   byte = 'i' // secondary and inverse indexes
	SubspaceQueue   byte = 'n' // SMTP queue / queue events
	SubspaceTags    byte = 't' // tags / small inline blobs
	SubspaceLookup  byte = 'l' // auxiliary lookups
	SubspaceAdmin   byte = 'a' // admin objects (msgpack)
	SubspaceAccount byte = 'u' // account / quota data
)
