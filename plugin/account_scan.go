// Account scan manifest: host-prepared message list for account_scan CLI profile.
package plugin

// AccountScanMessage is one mailbox message exposed as a readable body path.
type AccountScanMessage struct {
	Mailbox  string `json:"mailbox"`
	UID      uint32 `json:"uid"`
	BodyPath string `json:"body_path"`
}

// AccountScanManifest is written by the host before spawning a account_scan plugin job.
type AccountScanManifest struct {
	AccountEmail string               `json:"account_email"`
	Messages     []AccountScanMessage `json:"messages"`
}
