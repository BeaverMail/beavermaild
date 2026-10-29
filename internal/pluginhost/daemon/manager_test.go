package daemon_test

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/BeaverMail/beavermaild/internal/pluginhost"
	"github.com/BeaverMail/beavermaild/internal/pluginhost/daemon"
	"github.com/BeaverMail/beavermaild/internal/smtp"
	"github.com/BeaverMail/beavermaild/plugin"
)

func TestManagerLoadFromRegistrySMTP(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "beaver-plugin-antispam")
	if err := installBuiltPlugin(t, exe, "internal/pluginhost/testdata/daemonplugin"); err != nil {
		t.Fatal(err)
	}

	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	entries := reg.DaemonEntries()
	if len(entries) != 1 || entries[0].Name != "antispam" {
		t.Fatalf("daemon entries: %+v", entries)
	}
	if !entries[0].HasCapability(plugin.CapSMTP) {
		t.Fatal("expected smtp capability")
	}

	socketDir := filepath.Join(t.TempDir(), "sockets")
	m := daemon.NewManager(slog.Default(), daemon.Config{SocketDir: socketDir})
	if err := m.LoadFromRegistry(reg); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	f := m.Filter()
	out, err := f.Filter(t.Context(), smtp.FilterRequest{
		ID: "1", Phase: smtp.FilterPhaseEom, From: "a@b", To: []string{"c@d"}, ClientIP: "127.0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != smtp.FilterActionAccept {
		t.Fatalf("action %q", out.Action)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestManagerRejectActionFromPlugin(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "beaver-plugin-antispam")
	if err := installBuiltPlugin(t, exe, "internal/pluginhost/testdata/daemonplugin"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEAVER_TEST_DAEMON_ACTION", "reject")

	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := daemon.NewManager(slog.Default(), daemon.Config{SocketDir: filepath.Join(t.TempDir(), "sockets")})
	if err := m.LoadFromRegistry(reg); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	out, err := m.Filter().Filter(t.Context(), smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail})
	if err != nil {
		t.Fatal(err)
	}
	if out.Action != smtp.FilterActionReject {
		t.Fatalf("action %q", out.Action)
	}
	_ = m.Stop()
}

func TestManagerRestartAfterCrash(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "beaver-plugin-crashfilter")
	if err := installBuiltPlugin(t, exe, "internal/pluginhost/testdata/crashdaemonplugin"); err != nil {
		t.Fatal(err)
	}

	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := daemon.NewManager(slog.Default(), daemon.Config{
		SocketDir:      filepath.Join(t.TempDir(), "sockets"),
		RestartBackoff: 20 * time.Millisecond,
	})
	if err := m.LoadFromRegistry(reg); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if err := m.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer m.Stop()

	f := m.Filter()
	req := smtp.FilterRequest{ID: "1", Phase: smtp.FilterPhaseMail}
	out, err := f.Filter(ctx, req)
	if err != nil || out.Action != smtp.FilterActionAccept {
		t.Fatalf("first filter: %+v %v", out, err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		out, err = f.Filter(ctx, smtp.FilterRequest{ID: "2", Phase: smtp.FilterPhaseMail})
		if err == nil && out.Action == smtp.FilterActionAccept {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("plugin did not recover after crash")
}

func TestManagerStopNoRestart(t *testing.T) {
	dir := t.TempDir()
	exe := filepath.Join(dir, "beaver-plugin-crashfilter")
	if err := installBuiltPlugin(t, exe, "internal/pluginhost/testdata/crashdaemonplugin"); err != nil {
		t.Fatal(err)
	}
	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := daemon.NewManager(slog.Default(), daemon.Config{
		SocketDir:      filepath.Join(t.TempDir(), "sockets"),
		RestartBackoff: 10 * time.Millisecond,
	})
	if err := m.LoadFromRegistry(reg); err != nil {
		t.Fatal(err)
	}
	if err := m.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
}

func installBuiltPlugin(t *testing.T, dst, pkg string) error {
	t.Helper()
	root := findModuleRoot(t)
	out := filepath.Join(t.TempDir(), "plugin-build")
	cmd := exec.Command("go", "build", "-o", out, filepath.Join(root, pkg))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

func findModuleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
