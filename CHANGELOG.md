# Changelog

## Unreleased

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
