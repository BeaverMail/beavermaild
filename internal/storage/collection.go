// JMAP-aligned collection ids used in KV key prefixes.
package storage

// Collection is the document type byte in a storage key.
type Collection byte

// Collection ids (stable; do not renumber).
const (
	CollectionMailbox Collection = 1
	CollectionEmail   Collection = 2
	CollectionThread  Collection = 3
	CollectionIdentity Collection = 4
	CollectionEmailSubmission Collection = 5
	CollectionSieveScript Collection = 6
	CollectionPushSubscription Collection = 7
	CollectionPrincipal Collection = 8
	CollectionCalendar Collection = 9
	CollectionCalendarEvent Collection = 10
	CollectionAddressBook Collection = 11
	CollectionContactCard Collection = 12
	CollectionFileNode Collection = 13
	CollectionCalendarEventNotification Collection = 14
	// CollectionMailboxEmailIndex maps mailbox membership in SubspaceIndex (suffix = email id).
	CollectionMailboxEmailIndex Collection = 15
)

// DocumentSuffix builds a batch suffix from collection, document id, and optional tail.
func DocumentSuffix(collection Collection, documentID uint32, tail []byte) []byte {
	return BatchSuffix(byte(collection), documentID, tail)
}
