// IMAP SELECT response counters derived from mailbox message lists.
package mail

// MailboxSelectState returns UIDNEXT, UNSEEN, and effective HIGHESTMODSEQ for SELECT.
func MailboxSelectState(msgs []Message, storedHighest uint64) (uidNext, unseen uint32, highestMod uint64) {
	uidNext = 1
	for _, m := range msgs {
		if m.Meta.Flags&FlagSeen == 0 {
			unseen++
		}
		if m.UID >= uidNext {
			uidNext = m.UID + 1
		}
		if m.Meta.ModSeq > highestMod {
			highestMod = m.Meta.ModSeq
		}
	}
	if storedHighest > highestMod {
		highestMod = storedHighest
	}
	return uidNext, unseen, highestMod
}
