package cli_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/BeaverMail/beaver/internal/config"
	"github.com/BeaverMail/beaver/internal/directory"
	"github.com/BeaverMail/beaver/internal/pluginhost"
	"github.com/BeaverMail/beaver/internal/pluginhost/cli"
	"github.com/BeaverMail/beaver/internal/runtime"
	"github.com/BeaverMail/beaver/plugin"
)

func TestCLIIngestPlugin(t *testing.T) {
	root := findModuleRoot(t)
	pluginExe := filepath.Join(t.TempDir(), "beaver-plugin-stub")
	out, err := exec.Command("go", "build", "-o", pluginExe,
		filepath.Join(root, "internal/pluginhost/cli/testdata/stubplugin")).CombinedOutput()
	if err != nil {
		t.Fatalf("build stub plugin: %v\n%s", err, out)
	}

	dataDir := t.TempDir()
	cfg, err := config.InitLayout(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	stack, err := runtime.OpenMailStack(ctx, cfg.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	dom, _, err := directory.NewLocal(stack.Store).EnsureDomain(ctx, directory.DefaultTenantID, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	_, err = directory.NewLocal(stack.Store).CreateAccount(ctx, dom.ID, "alice", "secret")
	if err != nil {
		t.Fatal(err)
	}
	_ = stack.Close()

	pluginsDir := filepath.Join(dataDir, "plugins")
	if err := os.MkdirAll(pluginsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stubName := "beaver-plugin-stub"
	if err := os.WriteFile(filepath.Join(pluginsDir, stubName), readFile(t, pluginExe), 0o755); err != nil {
		t.Fatal(err)
	}

	res, err := cli.Run(ctx, cli.RunOptions{
		ConfigPath:    cfg.ConfigPath(),
		BeaverVersion: "test",
		ClearRecent:   true,
		Entry: pluginhost.Entry{
			Name:         "stub",
			Command:      []string{"test", "ingest"},
			Exe:          stubName,
			Capabilities: []string{plugin.CapCLI},
		},
		Request: plugin.CliRequest{
			AccountEmail: "alice@example.com",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Imported != 1 {
		t.Fatalf("imported=%d want 1", res.Imported)
	}
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
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
