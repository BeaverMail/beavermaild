package pluginhost

import (
	"testing"

	"github.com/BeaverMail/beaver/plugin"
)

func TestProfileForCommand(t *testing.T) {
	ingest := Entry{Command: []string{"widget", "frob"}}
	if p, err := ingest.ProfileForCommand([]string{"widget", "frob"}); err != nil || p != plugin.CliProfileIngest {
		t.Fatalf("ingest profile: %q err=%v", p, err)
	}

	admin := Entry{
		Command: []string{"filter"},
		CliKind: plugin.CliKindAdmin,
		CliSubcommands: []plugin.CliSubcommand{
			{Name: "reload", Profile: plugin.CliProfileJob},
			{Name: "scan", Profile: plugin.CliProfileAccountScan},
		},
	}
	if p, err := admin.ProfileForCommand([]string{"filter", "reload"}); err != nil || p != plugin.CliProfileJob {
		t.Fatalf("job profile: %q err=%v", p, err)
	}
	if p, err := admin.ProfileForCommand([]string{"filter", "scan"}); err != nil || p != plugin.CliProfileAccountScan {
		t.Fatalf("scan profile: %q err=%v", p, err)
	}
	if _, err := admin.ProfileForCommand([]string{"filter"}); err == nil {
		t.Fatal("expected error for bare filter")
	}
}

func TestRequiresAccount(t *testing.T) {
	if !RequiresAccount(plugin.CliProfileIngest) || !RequiresAccount(plugin.CliProfileAccountScan) {
		t.Fatal("ingest and account_scan require account")
	}
	if RequiresAccount(plugin.CliProfileJob) {
		t.Fatal("job must not require account")
	}
}
