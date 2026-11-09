# Changelog

## Unreleased

- IMAP FETCH: `BODY[n]` returns the part content only, as RFC 3501 requires; it included the part's MIME
  header, which is `BODY[n.MIME]`. Section bytes are returned as stored: quoted-printable parts were
  decoded and part headers reordered.
- IMAP FETCH: part numbers continue into `message/rfc822` parts (`BODY[2.1]`), and `HEADER`/`TEXT`/
  `HEADER.FIELDS` of such a part refer to the encapsulated message; they returned the outer message.
  `HEADER.FIELDS.NOT` and part-prefixed `HEADER.FIELDS` (`BODY[1.HEADER.FIELDS (...)]`) are supported.
  Parts of a `multipart/digest` without `Content-Type` are `message/rfc822` (RFC 2046), in FETCH and
  BODYSTRUCTURE.
- IMAP BODYSTRUCTURE: part sizes and encodings come from the raw part, like `BODY[n]`; quoted-printable
  parts were measured decoded.
- IMAP SEARCH: `SENTBEFORE`/`SENTON`/`SENTSINCE` use the day written in the `Date` header, ignoring its time
  and zone; they compared the UTC day. Address criteria (`FROM`, `TO`, `CC`, `BCC`) also match addresses
  written with RFC 5322 comments.
- IMAP: `SELECT`/`EXAMINE` and `APPEND` no longer create a missing folder (RFC 3501). `SELECT` answers `NO`;
  `APPEND` answers `NO [TRYCREATE]` before the literal, so the client can `CREATE` and retry. Clients that
  relied on the implicit creation must send `CREATE` first. An invalid name in `SELECT` answers `NO`.
- IMAP APPEND: a refused `APPEND` with a non-synchronizing literal (`{n+}`) consumes the literal; its bytes
  were read as commands.
- IMAP: reversed sequence ranges (`3:1`, `*:4`) are accepted as RFC 3501 allows, and a UID range past the
  largest UID (`9:*`) still matches the last message; they got `BAD` or matched nothing.
- IMAP FETCH: `BODY` (non-extensible body structure) and the `FAST`/`ALL`/`FULL` macros; they got `BAD`.
- IMAP FETCH: `BODY[...]` without `PEEK`, `RFC822` and `RFC822.TEXT` set `\Seen` in a read-write mailbox and
  report the new `FLAGS`, as RFC 3501 requires.
- IMAP SEARCH: an empty string (`SUBJECT ""`) matches every message instead of `BAD`; `HEADER field ""`
  matches only messages that have the field; a repeated field matches on any of its occurrences.
- IMAP `CLOSE` after `EXAMINE` answers `OK` and expunges nothing; it answered `NO mailbox is read-only`.
- IMAP: system flags are case-insensitive (`\seen` is `\Seen`) in APPEND, STORE and SEARCH; lowercase flags
  were ignored on APPEND and stored as keywords on STORE.
- IMAP STORE: `FLAGS` (replace, without `.SILENT`) answers with the untagged `FETCH`, as `+FLAGS`/`-FLAGS` do,
  and replaces keywords too; they were kept, and keywords in the list were dropped.
- IMAP `DELETE` removes a folder together with its messages, as RFC 3501 requires; it refused non-empty
  folders with `NO mailbox not empty`. System folders stay protected.
- IMAP: `SELECT`/`EXAMINE` accept the `(CONDSTORE)` select parameter; the parameter list was taken as part
  of the mailbox name, which created a folder called `INBOX (CONDSTORE)`. Unknown parameters get `BAD`.
- IMAP: a `SELECT`/`EXAMINE` with an invalid mailbox name answers `BAD` and keeps the session open; it closed
  the connection.
- IMAP STORE: a failed `UNCHANGEDSINCE` answers `OK [MODIFIED set] Conditional STORE failed` with the messages
  left unchanged (sequence numbers, or UIDs for `UID STORE`), as RFC 7162 requires.
- IMAP FETCH: the CONDSTORE modifier `(CHANGEDSINCE n)` returns only messages changed after mod-sequence `n`,
  each with `MODSEQ`; it was ignored and every message came back.
- IMAP: `STATUS` returns `HIGHESTMODSEQ` (RFC 7162, required with CONDSTORE), and `ENABLE` is advertised in
  CAPABILITY.
- IMAP FETCH: strings with non-ASCII bytes in ENVELOPE and BODYSTRUCTURE (decoded sender names, RFC 2231
  filenames) are sent as literals: IMAP4rev1 quoted strings are 7-bit only.
- IMAP FETCH: partial fetches `BODY[...]<origin.count>` return the requested byte range.
- IMAP SEARCH: `CHARSET` (UTF-8 and US-ASCII; others get `NO [BADCHARSET]`), literal search strings, bare
  sequence sets, `UID` with sequence-set lists, and the CONDSTORE `MODSEQ` criterion with `(MODSEQ n)` in the
  SEARCH and SORT responses.
- IMAP SEARCH: header criteria match RFC 2047 encoded words decoded, so UTF-8 searches find encoded subjects
  and names.
- IMAP SORT/THREAD: accept the charset argument RFC 5256 requires; a search program with parentheses after the
  sort keys no longer fails with `BAD`.
- IMAP THREAD: thread lists in the response follow each other with no space (`(1 2)(5)`), as RFC 5256 requires.
- IMAP BODYSTRUCTURE: an empty MIME parameter value (e.g. `name=""`) is sent as `""` instead of `NIL`, which
  strict clients rejected as a parse error.
- IMAP SEARCH/SORT/THREAD stop when the client disconnects, instead of reading every message of the mailbox
  first; during shutdown they end with `NO [UNAVAILABLE]`.

## 0.3.0

- License: GNU AGPL v3.0 only (`AGPL-3.0-only`), copyright BLUEBOX SOFTWARE S.L. Contributions under the
  [CLA](CLA.md). Third-party notices in [NOTICE](NOTICE).
- Antispam plugin rewritten on the rspamd rules: rspamd symbol names, default scores and actions (greylist 4,
  add header 6, reject 15). **The config format changed:** rewrite `<data_dir>/antispam/config.json` from
  `examples/antispam/config.json.example` before upgrading; see [docs/antispam-ops.md](docs/antispam-ops.md).
  The list files keep their names.
- Security policy: [SECURITY.md](SECURITY.md).

## 0.2.0

- Debian package (`make deb`): installs `beaver` and the antispam plugin, a systemd unit and a loopback-only
  config on first install; the data directory is readable by its owner only.
- An API key closes `/setup`, for installs managed only by a provisioner.
- IMAP: full LIST-EXTENDED (RFC 5258) with the RFC 6154 special-use options.
- IMAP: `LIST "" ""` returns the hierarchy delimiter, and the reference is joined to the pattern.
- IMAP: `CREATE` makes the missing parent mailboxes; `LSUB` with `%` shows unsubscribed parents.
