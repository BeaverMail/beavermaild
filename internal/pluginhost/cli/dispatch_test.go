package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BeaverMail/beavermaild/internal/cli"
	"github.com/BeaverMail/beavermaild/internal/pluginhost"
	"github.com/BeaverMail/beavermaild/plugin"
)

func TestSplitCommandAndFlags(t *testing.T) {
	cmd, flags := splitCommandAndFlags([]string{"filter", "reload", "--account", "a@b.com"})
	if len(cmd) != 2 || cmd[0] != "filter" || cmd[1] != "reload" {
		t.Fatalf("cmd=%v", cmd)
	}
	if len(flags) != 2 {
		t.Fatalf("flags=%v", flags)
	}
}

func TestConfigFromArgs(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "def"},
		{[]string{"-account", "alice@example.com"}, "def"},
		{[]string{"-c", "/opt/b/config.json"}, "/opt/b/config.json"},
		{[]string{"-dry-run", "--c=/opt/b/config.json"}, "/opt/b/config.json"},
		{[]string{"-c"}, "def"},
	} {
		if got := configFromArgs(tc.args, "def"); got != tc.want {
			t.Fatalf("%v: got %q want %q", tc.args, got, tc.want)
		}
	}
}

func TestParsePluginFlags(t *testing.T) {
	p, err := parsePluginFlags([]string{
		"--account", "alice@example.com",
		"--param", "list=/etc/filters",
		"--dry-run",
	}, "/data/config.json", nil, plugin.CliProfileIngest)
	if err != nil {
		t.Fatal(err)
	}
	if p.account != "alice@example.com" || p.params["list"] != "/etc/filters" || !p.dryRun {
		t.Fatalf("%+v", p)
	}
}

func TestParsePluginFlagsDescriptorCLI(t *testing.T) {
	p, err := parsePluginFlags([]string{
		"--account", "alice@example.com",
		"--srcdir", "/var/data/src",
	}, "/data/config.json", []plugin.CliFlag{
		{Key: "srcdir", Flag: "srcdir", Required: true},
	}, plugin.CliProfileIngest)
	if err != nil {
		t.Fatal(err)
	}
	if p.params["srcdir"] != "/var/data/src" {
		t.Fatalf("srcdir=%q", p.params["srcdir"])
	}
}

func TestParsePluginFlagsDescriptorCLIRequired(t *testing.T) {
	_, err := parsePluginFlags([]string{
		"--account", "alice@example.com",
	}, "/data/config.json", []plugin.CliFlag{
		{Key: "srcdir", Flag: "srcdir", Required: true},
	}, plugin.CliProfileIngest)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "-srcdir is required") {
		t.Fatalf("err=%v", err)
	}
}

func TestPluginFlagHintScanOnly(t *testing.T) {
	entry := pluginhost.Entry{Command: []string{"widget-frob"}}
	err := fmt.Errorf("flag provided but not defined: -srcdir")
	if got := pluginFlagHint(entry, err); got == "" {
		t.Fatal("expected hint")
	}
	if got := pluginFlagHint(pluginhost.Entry{CliFlags: []plugin.CliFlag{{Flag: "srcdir"}}}, err); got != "" {
		t.Fatalf("unexpected hint: %q", got)
	}
}

func TestParsePluginFlagsAdminSkipsAccount(t *testing.T) {
	p, err := parsePluginFlags([]string{"-c", "/data/config.json"}, "/data/config.json", nil, plugin.CliProfileJob)
	if err != nil {
		t.Fatal(err)
	}
	if p.account != "" {
		t.Fatalf("account=%q", p.account)
	}
}

func TestParsePluginFlagsRequiresAccount(t *testing.T) {
	_, err := parsePluginFlags([]string{"--param", "list=/x"}, "/data/config.json", nil, plugin.CliProfileIngest)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestFindCLIByPrefix(t *testing.T) {
	dir := t.TempDir()
	if err := installPlugin(t, dir, "beaver-plugin-widget-frob", "internal/pluginhost/testdata/metadataplugin"); err != nil {
		t.Fatal(err)
	}
	if err := installPlugin(t, dir, "beaver-plugin-filter-reload", "internal/pluginhost/testdata/filterplugin"); err != nil {
		t.Fatal(err)
	}
	if err := installPlugin(t, dir, "beaver-plugin-filter-list", "internal/pluginhost/testdata/filterlistplugin"); err != nil {
		t.Fatal(err)
	}
	reg, err := pluginhost.LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got := reg.FindCLIByPrefix([]string{"widget"}); len(got) != 1 || got[0].Op() != "widget/frob" {
		t.Fatalf("widget prefix: %+v", got)
	}
	if got := reg.FindCLIByPrefix([]string{"filter"}); len(got) != 2 {
		t.Fatalf("filter prefix: %+v", got)
	}
	if got := reg.FindCLIByPrefix([]string{"nope"}); len(got) != 0 {
		t.Fatalf("nope prefix: %+v", got)
	}
}

func TestTryDispatchAdminPluginBarePrefixShowsUsage(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	pluginsDir := filepath.Join(dataDir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dataDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir":"data"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEAVER_CONFIG", cfgPath)
	if err := installPlugin(t, pluginsDir, "beaver-plugin-filter-admin", "internal/pluginhost/testdata/adminfilterplugin"); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)

	code, ok := TryDispatch(t.Context(), DispatchOptions{Args: []string{"filter"}})
	if !ok {
		t.Fatal("expected filter bare prefix to dispatch to usage")
	}
	if code != cli.ExitUsage {
		t.Fatalf("code=%d want usage", code)
	}
}

func TestTryDispatchPluginCommand(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	pluginsDir := filepath.Join(dataDir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(dataDir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"data_dir":"data"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BEAVER_CONFIG", cfgPath)
	if err := installPlugin(t, pluginsDir, "beaver-plugin-widget-frob", "internal/pluginhost/testdata/metadataplugin"); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)

	code, ok := TryDispatch(t.Context(), DispatchOptions{Args: []string{"widget", "frob"}})
	if !ok {
		t.Fatal("expected plugin dispatch")
	}
	if code != cli.ExitUsage {
		t.Fatalf("code=%d want usage", code)
	}

	if _, ok := TryDispatch(t.Context(), DispatchOptions{Args: []string{"widget-frob"}}); ok {
		t.Fatal("widget-frob must not dispatch when list shows widget frob")
	}
}

func installPlugin(t *testing.T, dir, name, pkg string) error {
	t.Helper()
	root := findModuleRoot(t)
	out := filepath.Join(t.TempDir(), name)
	cmd := exec.Command("go", "build", "-o", out, filepath.Join(root, pkg))
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s: %v\n%s", pkg, err, b)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, name), b, 0o755)
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
