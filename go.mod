module github.com/BeaverMail/beavermaild

go 1.26.0

require (
	github.com/go-sql-driver/mysql v1.11.0
	github.com/pierrec/lz4/v4 v4.1.34
	github.com/vmihailenco/msgpack/v5 v5.4.1
	github.com/zeebo/blake3 v0.2.4
	github.com/zeebo/xxh3 v1.1.0
	golang.org/x/crypto v0.59.0
	modernc.org/sqlite v1.63.0
)

require filippo.io/edwards25519 v1.2.0 // indirect

require (
	github.com/dustin/go-humanize v1.1.0 // indirect
	github.com/emersion/go-msgauth v0.7.0
	github.com/google/uuid v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.2 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/miekg/dns v1.1.73
	github.com/ncruces/go-strftime v1.1.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/stretchr/testify v1.8.3 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	golang.org/x/net v0.63.0
	golang.org/x/sys v0.50.0 // indirect
	golang.org/x/text v0.44.0
	golang.org/x/tools v0.53.0 // indirect
	modernc.org/libc v1.82.14 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.13.1 // indirect
)

// Fork with linear header reading in dkim (quadratic in folded lines upstream), until a release has the fix.
replace github.com/emersion/go-msgauth => github.com/BeaverMail/go-msgauth v0.7.1-beavermail.1
